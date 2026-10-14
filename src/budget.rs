//! Finite work, logical reservations, and cooperative cancellation.
use crate::error::{ErrorCode as E, Result};
use serde::Serialize;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_work: u64,
    pub max_reserved_bytes: usize,
    pub max_output_rows: usize,
    pub max_output_bytes: usize,
    pub batch_rows: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_work: 10_000_000,
            max_reserved_bytes: 64 * 1024 * 1024,
            max_output_rows: 10_000,
            max_output_bytes: 1024 * 1024,
            batch_rows: 1024,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        let defaults = Self::default();
        if self.max_work > defaults.max_work
            || self.max_reserved_bytes > defaults.max_reserved_bytes
            || self.max_output_rows > defaults.max_output_rows
            || self.max_output_bytes > defaults.max_output_bytes
            || self.batch_rows == 0
            || self.batch_rows > defaults.batch_rows
        {
            return Err(E::Context.into());
        }
        Ok(())
    }
}
#[derive(Debug)]
struct Memory {
    used: Cell<usize>,
    peak: Cell<usize>,
    corrupt: Cell<bool>,
    max: usize,
}
#[derive(Debug)]
pub(crate) struct Reservation {
    meter: Rc<Memory>,
    bytes: usize,
}
impl Reservation {
    pub fn grow(&mut self, bytes: usize) -> Result<()> {
        if self.meter.corrupt.get() {
            return Err(E::Internal.into());
        }
        let next = self.meter.used.get().checked_add(bytes).ok_or(E::Budget)?;
        let owned = self.bytes.checked_add(bytes).ok_or(E::Budget)?;
        if next > self.meter.max {
            return Err(E::Budget.into());
        }
        self.meter.used.set(next);
        self.meter.peak.set(self.meter.peak.get().max(next));
        self.bytes = owned;
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(next) = self.meter.used.get().checked_sub(self.bytes) {
            self.meter.used.set(next);
        } else {
            self.meter.corrupt.set(true);
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Metrics {
    pub work_units: u64,
    pub peak_reserved_bytes: usize,
}

pub struct Budget {
    limits: Limits,
    work: u64,
    visible_work: u64,
    memory: Rc<Memory>,
    scans: u32,
    cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
    observer: Option<Box<dyn FnMut(&'static str) -> Result<()>>>,
}
impl Budget {
    pub fn new(
        limits: Limits,
        cancelled: Arc<AtomicBool>,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        limits.validate()?;
        let memory = Rc::new(Memory {
            used: Cell::new(0),
            peak: Cell::new(0),
            corrupt: Cell::new(false),
            max: limits.max_reserved_bytes,
        });
        Ok(Self {
            limits,
            work: 0,
            visible_work: 0,
            memory,
            cancelled,
            deadline,
            scans: 0,
            observer: None,
        })
    }
    pub fn checkpoint(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire)
            || self.deadline.is_some_and(|d| Instant::now() >= d)
        {
            return Err(E::Cancelled.into());
        }
        if self.memory.corrupt.get() {
            return Err(E::Internal.into());
        }
        Ok(())
    }
    /// Trusted test/measurement hook; query input cannot install an observer.
    pub fn set_observer(&mut self, observer: impl FnMut(&'static str) -> Result<()> + 'static) {
        self.observer = Some(Box::new(observer));
    }
    pub(crate) fn observe(&mut self, stage: &'static str) -> Result<()> {
        if let Some(observer) = &mut self.observer {
            observer(stage)?;
        }
        self.checkpoint()
    }
    pub fn charge(&mut self, amount: u64) -> Result<()> {
        self.charge_inner(amount, true)
    }
    pub(crate) fn charge_hidden(&mut self, amount: u64) -> Result<()> {
        self.charge_inner(amount, false)
    }
    fn charge_inner(&mut self, amount: u64, visible: bool) -> Result<()> {
        self.checkpoint()?;
        let next = self.work.checked_add(amount).ok_or(E::Budget)?;
        if next > self.limits.max_work {
            return Err(E::Budget.into());
        }
        self.work = next;
        if visible {
            self.visible_work = self.visible_work.checked_add(amount).ok_or(E::Budget)?;
        }
        Ok(())
    }
    pub(crate) fn reserve(&self, bytes: usize) -> Result<Reservation> {
        self.checkpoint()?;
        let mut reservation = Reservation {
            meter: self.memory.clone(),
            bytes: 0,
        };
        reservation.grow(bytes)?;
        Ok(reservation)
    }
    pub fn consumed_work(&self) -> u64 {
        self.work
    }
    pub fn executed_scans(&self) -> u32 {
        self.scans
    }
    pub(crate) fn start_scan(&mut self) -> Result<()> {
        self.observe("scan_open")?;
        self.scans = self.scans.checked_add(1).ok_or(E::Budget)?;
        Ok(())
    }
    pub fn reserved_bytes(&self) -> usize {
        self.memory.used.get()
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn metrics(&self) -> Metrics {
        Metrics {
            work_units: self.visible_work,
            peak_reserved_bytes: self.memory.peak.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_release_on_error_and_limits_fail_before_growth() -> Result<()> {
        let budget = Budget::new(
            Limits {
                max_reserved_bytes: 10,
                ..Limits::default()
            },
            Arc::new(AtomicBool::new(false)),
            None,
        )?;
        {
            let mut r = budget.reserve(8)?;
            assert_eq!(r.grow(3).map_err(|e| e.code), Err(E::Budget));
            assert_eq!(budget.reserved_bytes(), 8);
        }
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.metrics().peak_reserved_bytes, 8);
        Ok(())
    }
    #[test]
    fn charge_never_exceeds_limit_and_cancel_precedes_allocation() -> Result<()> {
        let flag = Arc::new(AtomicBool::new(false));
        let mut budget = Budget::new(
            Limits {
                max_work: 2,
                ..Limits::default()
            },
            flag.clone(),
            None,
        )?;
        budget.charge_hidden(1)?;
        budget.charge(1)?;
        assert_eq!(budget.metrics().work_units, 1);
        assert_eq!(budget.charge(1).map_err(|e| e.code), Err(E::Budget));
        assert_eq!(budget.consumed_work(), 2);
        flag.store(true, Ordering::Release);
        assert_eq!(budget.reserve(1).err().map(|e| e.code), Some(E::Cancelled));
        Ok(())
    }
}
