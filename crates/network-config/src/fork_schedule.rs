//! The Fulu/Gloas fork schedule of one network.
//!
//! Only Fulu and Gloas are in scope, so an epoch before `FULU_FORK_EPOCH` has no fork here
//! ([`ForkSchedule::fork_at`] returns `None`) and callers must refuse such objects.

use std::fmt;
use std::str::FromStr;

/// An epoch number (`phase0/beacon-chain.md` `Epoch`).
pub type Epoch = u64;
/// A 4-byte fork version (`phase0/beacon-chain.md` `Version`).
pub type Version = [u8; 4];
/// `FAR_FUTURE_EPOCH`: a fork scheduled here is not scheduled at all.
pub const FAR_FUTURE_EPOCH: Epoch = u64::MAX;

/// A fork this client decodes. Ordered by activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ForkName {
    /// Fulu (PeerDAS, EIP-7594).
    Fulu,
    /// Gloas (ePBS, EIP-7732; progressive SSZ, EIP-7688).
    Gloas,
}

impl ForkName {
    /// Every fork, oldest first.
    pub const ALL: [ForkName; 2] = [ForkName::Fulu, ForkName::Gloas];

    /// The lowercase name used in spec paths and test vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            ForkName::Fulu => "fulu",
            ForkName::Gloas => "gloas",
        }
    }
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An unknown fork name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown fork {0:?} (expected fulu or gloas)")]
pub struct UnknownFork(pub String);

impl FromStr for ForkName {
    type Err = UnknownFork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ForkName::ALL
            .into_iter()
            .find(|f| f.as_str() == s)
            .ok_or_else(|| UnknownFork(s.to_owned()))
    }
}

/// One scheduled fork: its version and activation epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduledFork {
    /// `<FORK>_FORK_VERSION`.
    pub version: Version,
    /// `<FORK>_FORK_EPOCH`; [`FAR_FUTURE_EPOCH`] means not scheduled.
    pub epoch: Epoch,
}

/// The schedule is not ordered by activation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("GLOAS_FORK_EPOCH {gloas} is before FULU_FORK_EPOCH {fulu}")]
pub struct ScheduleOrderError {
    /// `FULU_FORK_EPOCH`.
    pub fulu: Epoch,
    /// `GLOAS_FORK_EPOCH`.
    pub gloas: Epoch,
}

/// Fork versions and activation epochs for Fulu and Gloas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkSchedule {
    fulu: ScheduledFork,
    gloas: ScheduledFork,
}

impl ForkSchedule {
    /// Builds a schedule; Gloas must not activate before Fulu.
    pub fn new(fulu: ScheduledFork, gloas: ScheduledFork) -> Result<Self, ScheduleOrderError> {
        if gloas.epoch < fulu.epoch {
            return Err(ScheduleOrderError {
                fulu: fulu.epoch,
                gloas: gloas.epoch,
            });
        }
        Ok(Self { fulu, gloas })
    }

    fn get(&self, fork: ForkName) -> &ScheduledFork {
        match fork {
            ForkName::Fulu => &self.fulu,
            ForkName::Gloas => &self.gloas,
        }
    }

    /// The fork active at `epoch`, or `None` before Fulu.
    pub fn fork_at(&self, epoch: Epoch) -> Option<ForkName> {
        ForkName::ALL
            .into_iter()
            .rev()
            .find(|&f| self.fork_epoch(f).is_some_and(|start| epoch >= start))
    }

    /// The activation epoch, or `None` when the fork is not scheduled.
    pub fn fork_epoch(&self, fork: ForkName) -> Option<Epoch> {
        Some(self.get(fork).epoch).filter(|&e| e != FAR_FUTURE_EPOCH)
    }

    /// The fork version.
    pub fn fork_version(&self, fork: ForkName) -> Version {
        self.get(fork).version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(epoch: Epoch) -> ScheduledFork {
        ScheduledFork {
            version: [0; 4],
            epoch,
        }
    }

    #[test]
    fn fork_names_parse() {
        for f in ForkName::ALL {
            assert_eq!(f.as_str().parse::<ForkName>(), Ok(f));
            assert_eq!(f.to_string(), f.as_str());
        }
        assert!("electra".parse::<ForkName>().is_err());
    }

    #[test]
    fn same_epoch_activates_the_later_fork() {
        let s = ForkSchedule::new(at(5), at(5)).unwrap();
        assert_eq!(s.fork_at(4), None);
        assert_eq!(s.fork_at(5), Some(ForkName::Gloas));
    }

    #[test]
    fn unscheduled_fulu_means_no_fork() {
        let s = ForkSchedule::new(at(FAR_FUTURE_EPOCH), at(FAR_FUTURE_EPOCH)).unwrap();
        assert_eq!(s.fork_at(FAR_FUTURE_EPOCH), None);
        assert_eq!(s.fork_epoch(ForkName::Fulu), None);
    }

    #[test]
    fn rejects_gloas_before_fulu() {
        assert_eq!(
            ForkSchedule::new(at(10), at(9)),
            Err(ScheduleOrderError { fulu: 10, gloas: 9 })
        );
    }
}
