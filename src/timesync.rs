//! Clock synchronization: `client/time` emission and `server/time` handling.

use std::time::Duration;

use crate::timefilter::TimeFilter;

/// Send interval while the filter is not yet converged.
const UNSYNCED_INTERVAL: Duration = Duration::from_millis(200);

/// Map the filter's current error to the next send interval.
pub fn sync_interval(filter: &TimeFilter) -> Duration {
    if !filter.is_synchronized() {
        return UNSYNCED_INTERVAL;
    }
    let error = filter.error();
    if error < 1_000 {
        Duration::from_secs(3)
    } else if error < 2_000 {
        Duration::from_secs(1)
    } else if error < 5_000 {
        Duration::from_millis(500)
    } else {
        Duration::from_millis(200)
    }
}

/// Feed a `server/time` exchange into the filter.
///
/// `client_transmitted` echoes our outgoing timestamp, `server_received` and
/// `server_transmitted` come from the server, and `received_us` is the local time at
/// which the reply arrived.
pub fn apply_server_time(
    filter: &mut TimeFilter,
    client_transmitted: i64,
    server_received: i64,
    server_transmitted: i64,
    received_us: i64,
) {
    let offset = ((server_received - client_transmitted) + (server_transmitted - received_us)) / 2;
    let delay = ((received_us - client_transmitted) - (server_transmitted - server_received)) / 2;
    filter.update(offset, delay, received_us);
}
