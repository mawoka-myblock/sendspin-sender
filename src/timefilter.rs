//! Two-dimensional Kalman time filter, a direct port of the reference `time_sync.py`.

/// Residual threshold as a multiple of `max_error` for adaptive forgetting.
const ADAPTIVE_FORGETTING_CUTOFF: f64 = 3.0;
/// Scale applied to `max_error` before it is used as the measurement standard deviation.
const MAX_ERROR_SCALE: f64 = 0.5;
/// Drift is only applied when `drift^2 > threshold^2 * drift_covariance`.
const DRIFT_SIGNIFICANCE_THRESHOLD_SQUARED: f64 = 2.0 * 2.0;

/// The current time transformation parameters.
#[derive(Default, Clone)]
struct TimeElement {
    last_update: i64,
    offset: f64,
    drift: f64,
    use_drift: bool,
}

pub struct TimeFilter {
    last_update: i64,
    count: u64,
    offset: f64,
    drift: f64,
    offset_covariance: f64,
    offset_drift_covariance: f64,
    drift_covariance: f64,
    process_variance: f64,
    drift_process_variance: f64,
    forget_variance_factor: f64,
    current: TimeElement,
}

impl Default for TimeFilter {
    fn default() -> Self {
        Self::new(0.0, 2.0, 1e-11)
    }
}

impl TimeFilter {
    pub fn new(process_std_dev: f64, forget_factor: f64, drift_process_std_dev: f64) -> Self {
        Self {
            last_update: 0,
            count: 0,
            offset: 0.0,
            drift: 0.0,
            offset_covariance: f64::INFINITY,
            offset_drift_covariance: 0.0,
            drift_covariance: 0.0,
            process_variance: process_std_dev * process_std_dev,
            drift_process_variance: drift_process_std_dev * drift_process_std_dev,
            forget_variance_factor: forget_factor * forget_factor,
            current: TimeElement::default(),
        }
    }

    /// Reset the filter to its initial state, keeping its tuning parameters.
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        *self = Self::new(
            self.process_variance.sqrt(),
            self.forget_variance_factor.sqrt(),
            self.drift_process_variance.sqrt(),
        );
    }

    /// Feed one NTP-style measurement: a computed offset with its bounded uncertainty.
    pub fn update(&mut self, measurement: i64, max_error: i64, time_added: i64) {
        if time_added <= self.last_update {
            return;
        }
        let dt: f64 = (time_added - self.last_update) as f64;
        self.last_update = time_added;
        let update_std_dev = max_error as f64 * MAX_ERROR_SCALE;
        let measurement_variance = update_std_dev * update_std_dev;

        if self.count == 0 {
            self.count = 1;
            self.offset = measurement as f64;
            self.offset_covariance = measurement_variance;
            self.drift = 0.0;
            self.current = TimeElement {
                last_update: self.last_update,
                offset: self.offset,
                drift: self.drift,
                use_drift: false,
            };
            return;
        }

        if self.count == 1 {
            self.count = 2;
            self.drift = (measurement as f64 - self.offset) / dt;
            self.offset = measurement as f64;
            self.drift_covariance = (self.offset_covariance + measurement_variance) / (dt * dt);
            self.offset_covariance = measurement_variance;
            self.current = TimeElement {
                last_update: self.last_update,
                offset: self.offset,
                drift: self.drift,
                use_drift: false,
            };
            return;
        }

        // Prediction step.
        let offset = self.offset + self.drift * dt;
        let dt_squared = dt * dt;
        let drift_process_variance = dt * self.drift_process_variance;
        let new_drift_covariance = self.drift_covariance + drift_process_variance;
        let new_offset_drift_covariance = self.offset_drift_covariance + self.drift_covariance * dt;
        let offset_process_variance = dt * self.process_variance;
        let mut new_offset_covariance = self.offset_covariance
            + 2.0 * self.offset_drift_covariance * dt
            + self.drift_covariance * dt_squared
            + offset_process_variance;
        let mut new_drift_covariance = new_drift_covariance;
        let mut new_offset_drift_covariance = new_offset_drift_covariance;

        // Innovation and adaptive forgetting.
        let residual = measurement as f64 - offset;
        let max_residual_cutoff = max_error as f64 * ADAPTIVE_FORGETTING_CUTOFF;
        if self.count < 100 {
            self.count += 1;
        } else if residual.abs() > max_residual_cutoff {
            new_drift_covariance *= self.forget_variance_factor;
            new_offset_drift_covariance *= self.forget_variance_factor;
            new_offset_covariance *= self.forget_variance_factor;
        }

        // Update step.
        let uncertainty = 1.0 / (new_offset_covariance + measurement_variance).max(1e-9);
        let offset_gain = new_offset_covariance * uncertainty;
        let drift_gain = new_offset_drift_covariance * uncertainty;

        self.offset = offset + offset_gain * residual;
        self.drift += drift_gain * residual;

        self.drift_covariance = new_drift_covariance - drift_gain * new_offset_drift_covariance;
        self.offset_drift_covariance =
            new_offset_drift_covariance - drift_gain * new_offset_covariance;
        self.offset_covariance = new_offset_covariance - offset_gain * new_offset_covariance;

        let use_drift =
            self.drift * self.drift > DRIFT_SIGNIFICANCE_THRESHOLD_SQUARED * self.drift_covariance;
        self.current = TimeElement {
            last_update: self.last_update,
            offset: self.offset,
            drift: self.drift,
            use_drift,
        };
    }

    /// Map a local (client) timestamp into the server's clock domain.
    pub fn compute_server_time(&self, client_time: i64) -> i64 {
        let element = &self.current;
        let effective_drift = if element.use_drift {
            element.drift
        } else {
            0.0
        };
        let dt = (client_time - element.last_update) as f64;
        let offset = (element.offset + effective_drift * dt).round() as i64;
        client_time + offset
    }

    /// Map a server timestamp back into the local (client) clock domain.
    #[allow(dead_code)]
    pub fn compute_client_time(&self, server_time: i64) -> i64 {
        let element = &self.current;
        let effective_drift = if element.use_drift {
            element.drift
        } else {
            0.0
        };
        ((server_time as f64 - element.offset + effective_drift * element.last_update as f64)
            / (1.0 + effective_drift))
            .round() as i64
    }

    /// Whether the filter holds enough history to be trusted.
    pub fn is_synchronized(&self) -> bool {
        self.count >= 2 && !self.offset_covariance.is_infinite()
    }

    /// The standard deviation estimate, in microseconds.
    pub fn error(&self) -> i64 {
        self.offset_covariance.sqrt().round() as i64
    }

    /// The number of measurements fed into the filter.
    #[allow(dead_code)]
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_synchronized_after_two_measurements() {
        let mut filter = TimeFilter::default();
        assert!(!filter.is_synchronized());
        filter.update(1_000, 50, 10_000);
        assert!(!filter.is_synchronized());
        filter.update(1_010, 50, 20_000);
        assert!(filter.is_synchronized());
        assert_eq!(filter.count(), 2);
    }

    #[test]
    fn server_and_client_time_are_inverses() {
        let mut filter = TimeFilter::default();
        // A steady +1000 us offset with a modest measurement noise.
        filter.update(1_000, 100, 1_000_000);
        filter.update(1_000, 100, 2_000_000);
        filter.update(1_000, 100, 3_000_000);

        let client = 5_000_000i64;
        let server = filter.compute_server_time(client);
        assert_eq!(server - client, 1_000);

        let back = filter.compute_client_time(server);
        assert!((back - client).abs() <= 1);
    }

    #[test]
    fn non_monotonic_updates_are_ignored() {
        let mut filter = TimeFilter::default();
        filter.update(500, 50, 1_000);
        filter.update(500, 50, 900);
        assert_eq!(filter.count(), 1);
    }

    #[test]
    fn reset_clears_synchronization() {
        let mut filter = TimeFilter::default();
        filter.update(0, 50, 1_000);
        filter.update(0, 50, 2_000);
        assert!(filter.is_synchronized());
        filter.reset();
        assert!(!filter.is_synchronized());
        assert_eq!(filter.count(), 0);
    }
}
