//! Test-only helpers shared across module unit tests.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;

use crate::runner::{CommandOutput, CommandRunner};

#[derive(Default)]
struct Inner {
    calls: RefCell<Vec<(String, Vec<String>)>>,
    responses: RefCell<VecDeque<io::Result<CommandOutput>>>,
}

/// A [`CommandRunner`] that records calls and replays scripted responses in
/// order. Cheaply cloneable (shared state) so a handle can be kept for
/// assertions after the runner is moved into a `Backend`.
#[derive(Clone, Default)]
pub struct MockRunner {
    inner: Rc<Inner>,
}

impl MockRunner {
    /// A runner with no scripted responses (each unqueued call returns success
    /// with empty output).
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a successful (exit `0`) response with the given stdout.
    pub fn ok(&self, stdout: &str) -> &Self {
        self.push(Ok(CommandOutput {
            code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
        }))
    }

    /// Queue a response that ran but exited non-zero with the given stderr.
    pub fn fail(&self, code: i32, stderr: &str) -> &Self {
        self.push(Ok(CommandOutput {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }))
    }

    /// Queue a spawn failure (as if the program were missing).
    pub fn spawn_err(&self) -> &Self {
        self.push(Err(io::Error::new(io::ErrorKind::NotFound, "missing")))
    }

    /// The `(program, args)` of every call made so far, in order.
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.inner.calls.borrow().clone()
    }

    fn push(&self, response: io::Result<CommandOutput>) -> &Self {
        self.inner.responses.borrow_mut().push_back(response);
        self
    }
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput> {
        self.inner
            .calls
            .borrow_mut()
            .push((program.to_string(), args.to_vec()));
        self.inner
            .responses
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| {
                Ok(CommandOutput {
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unscripted_calls_default_to_success_and_are_recorded() {
        let mock = MockRunner::new();
        let out = mock.run("wg", &["show".to_string()]).unwrap();
        assert!(out.success());
        assert!(out.stdout.is_empty());
        assert_eq!(
            mock.calls(),
            vec![("wg".to_string(), vec!["show".to_string()])]
        );
    }

    #[test]
    fn scripted_responses_replay_in_order() {
        let mock = MockRunner::new();
        mock.ok("first").fail(2, "boom").spawn_err();
        assert_eq!(mock.run("a", &[]).unwrap().stdout, "first");
        assert_eq!(mock.run("b", &[]).unwrap().code, Some(2));
        assert_eq!(
            mock.run("c", &[]).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
