use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

/// Manages a collection of threads.
///
/// A new thread is created every time all the existing threads are full.
/// Any idle thread will automatically die after a few seconds.
pub struct TaskPool {
    sharing: Arc<Sharing>,
}

struct Sharing {
    // [cipherlane patch 4] 待办队列与空闲线程计数放在同一把锁下。
    // 上游是 `todo: Mutex<VecDeque<..>>` 加一把独立的原子计数 `waiting_tasks`：
    // 线程在调用 wait 之前给计数加一、醒来回到循环之后才减一，于是"已经被
    // notify_one 唤醒、但还没抢到锁回到循环"的线程仍然被算作空闲。这期间到达的
    // spawn 以为有人在等，把任务塞进队列再 notify_one，而此刻已经没有真正睡在
    // condvar 上的线程，信号落空；被唤醒的线程各取走一个任务后，多出来的任务就一直
    // 躺在队列里，直到某个线程干完活回到循环才被捡起（对 keep-alive 连接来说就是
    // 一直没人读，直到别的连接关闭）。
    //
    // 现在空闲线程由 `waiting` / `reserved` 两个计数精确描述：
    //   waiting  —— 已登记为空闲、还没有被任何 spawn 预约的线程数
    //   reserved —— spawn 已经从 waiting 里扣掉、但还没被某个被唤醒线程认领的预约数
    // spawn 预约一个空闲线程（waiting -= 1, reserved += 1）后才 notify_one；被唤醒的
    // 线程回到循环时认领这笔预约（reserved -= 1）。于是任何时刻 waiting 都不会把
    // "已唤醒未回循环"的线程算进去：并发到达的 spawn 要么各预约到不同的线程，要么
    // 发现没有可预约的空闲线程而直接开新线程——任务不会被搁置。
    state: Mutex<State>,

    // condvar that will be notified whenever a task is added to `todo`
    condvar: Condvar,

    // number of total worker threads running
    active_tasks: AtomicUsize,
}

struct State {
    // list of the tasks to be done by worker threads
    todo: VecDeque<Box<dyn FnMut() + Send>>,

    // [cipherlane patch 4] 见 Sharing.state 的说明
    waiting: usize,
    reserved: usize,
}

/// Minimum number of active threads.
static MIN_THREADS: usize = 4;

struct Registration<'a> {
    nb: &'a AtomicUsize,
}

impl<'a> Registration<'a> {
    fn new(nb: &'a AtomicUsize) -> Registration<'a> {
        nb.fetch_add(1, Ordering::Release);
        Registration { nb }
    }
}

impl<'a> Drop for Registration<'a> {
    fn drop(&mut self) {
        self.nb.fetch_sub(1, Ordering::Release);
    }
}

impl TaskPool {
    pub fn new() -> TaskPool {
        let pool = TaskPool {
            sharing: Arc::new(Sharing {
                state: Mutex::new(State {
                    todo: VecDeque::new(),
                    waiting: 0,
                    reserved: 0,
                }),
                condvar: Condvar::new(),
                active_tasks: AtomicUsize::new(0),
            }),
        };

        for _ in 0..MIN_THREADS {
            pool.add_thread(None)
        }

        pool
    }

    /// Executes a function in a thread.
    /// If no thread is available, spawns a new one.
    pub fn spawn(&self, code: Box<dyn FnMut() + Send>) {
        {
            let mut state = self.sharing.state.lock().unwrap();

            if state.waiting > 0 {
                // [cipherlane patch 4] 预约一个空闲线程再 notify：之后到达的 spawn 不会再
                // 把这个线程当成可用（上游在这里读到的计数可能包含已唤醒未回循环的线程）
                state.waiting -= 1;
                state.reserved += 1;
                state.todo.push_back(code);
                self.sharing.condvar.notify_one();
                return;
            }
        }

        // 没有空闲线程可预约：直接开一个新线程执行
        self.add_thread(Some(code));
    }

    fn add_thread(&self, initial_fn: Option<Box<dyn FnMut() + Send>>) {
        let sharing = self.sharing.clone();

        thread::spawn(move || {
            let sharing = sharing;
            let _active_guard = Registration::new(&sharing.active_tasks);

            if let Some(mut f) = initial_fn {
                f();
            }

            loop {
                let mut task: Box<dyn FnMut() + Send> = {
                    let mut state = sharing.state.lock().unwrap();

                    let task;
                    loop {
                        if let Some(poped_task) = state.todo.pop_front() {
                            task = poped_task;
                            break;
                        }

                        // 没有任务：登记为空闲，然后去等
                        state.waiting += 1;

                        let received =
                            if sharing.active_tasks.load(Ordering::Acquire) <= MIN_THREADS {
                                state = sharing.condvar.wait(state).unwrap();
                                true
                            } else {
                                let (new_state, waitres) = sharing
                                    .condvar
                                    .wait_timeout(state, Duration::from_millis(5000))
                                    .unwrap();
                                state = new_state;
                                !waitres.timed_out()
                            };

                        // [cipherlane patch 4] 醒了。若是被 spawn 预约唤醒的，那笔预约已经
                        // 替我把 waiting 扣过了，这里只把它认领掉；否则（超时 / 虚假唤醒）
                        // 没人扣过，自己把空闲登记撤销。
                        if state.reserved > 0 {
                            state.reserved -= 1;
                        } else {
                            state.waiting = state.waiting.saturating_sub(1);
                        }

                        if !received && state.todo.is_empty() {
                            return;
                        }
                    }

                    task
                };

                task();
            }
        });
    }
}

impl Drop for TaskPool {
    fn drop(&mut self) {
        self.sharing
            .active_tasks
            .store(999_999_999, Ordering::Release);
        self.sharing.condvar.notify_all();
    }
}
