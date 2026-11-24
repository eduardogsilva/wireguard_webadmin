import base64
import math
import os
import subprocess

RRD_PEERS_PATH = '/rrd_data/peers'
# The RRD files keep 5 minute samples for a few days and coarser averages for older periods
DETAILED_RESOLUTION = 300
RESOLUTION_LABELS = {1800: '30 minutes', 7200: '2 hours', 86400: '1 day'}


class TrafficHistoryError(Exception):
    pass


def peer_rrd_path(peer):
    filename = base64.urlsafe_b64encode(peer.public_key.encode()).decode().replace('=', '')
    return os.path.join(RRD_PEERS_PATH, f'{filename}.rrd')


def _run_rrdtool(arguments):
    try:
        result = subprocess.run(['rrdtool', *arguments], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrafficHistoryError(str(error))
    if result.returncode != 0:
        raise TrafficHistoryError(result.stderr.strip() or f'rrdtool exited with status {result.returncode}')
    return result.stdout


def peer_traffic_totals(rrd_path, start, end):
    """Traffic of a peer between two timestamps (seconds), read from its RRD file.

    The RRD stores the average rate (bytes per second) of each interval; the total is the rate multiplied by the
    interval length. tx is what the server sent to the peer (the peer download) and rx what it received (upload).
    Returns a dict with the totals, the period effectively covered, the resolution and the intervals without data.
    """
    last_update = int(_run_rrdtool(['last', rrd_path]).strip())
    output = _run_rrdtool([
        'fetch', rrd_path, 'AVERAGE', '--start', str(int(start)), '--end', str(int(end)),
        '--resolution', str(DETAILED_RESOLUTION),
    ])

    lines = [line for line in output.splitlines() if line.strip()]
    columns = lines[0].split()
    tx_index, rx_index = columns.index('tx'), columns.index('rx')
    rows = []
    for line in lines[1:]:
        timestamp, _, values = line.partition(':')
        values = values.split()
        rows.append((int(timestamp), float(values[tx_index]), float(values[rx_index])))

    step = rows[1][0] - rows[0][0] if len(rows) > 1 else DETAILED_RESOLUTION
    # Each row covers the interval that ends at its timestamp; intervals after the last update are still open
    rows = [row for row in rows if row[0] <= last_update]

    download = upload = 0.0
    missing = 0
    for _, tx, rx in rows:
        if math.isnan(tx) or math.isnan(rx):
            missing += 1
            continue
        download += tx * step
        upload += rx * step

    return {
        'download_bytes': int(round(download)),
        'upload_bytes': int(round(upload)),
        'start': rows[0][0] - step if rows else int(start),
        'end': rows[-1][0] if rows else int(start),
        'resolution_seconds': step,
        'intervals': len(rows),
        'missing_intervals': missing,
    }


def traffic_warning(totals):
    """Short warning about the precision of the totals, or '' when they use the detailed history with no gaps."""
    warnings = []
    step = totals['resolution_seconds']
    if step > DETAILED_RESOLUTION:
        label = RESOLUTION_LABELS.get(step, f'{step} seconds')
        warnings.append(
            f'The period starts before the detailed history; the totals were calculated with a resolution of {label}.'
        )
    if totals['intervals'] == 0 or totals['missing_intervals'] == totals['intervals']:
        warnings.append('There is no traffic data in the requested period.')
    elif totals['missing_intervals']:
        warnings.append('Part of the period has no traffic data and is not included in the totals.')
    return ' '.join(warnings)
