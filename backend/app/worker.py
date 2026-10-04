"""Restricted local worker placeholder used by Docker Compose.

The interactive API executes the deterministic demo suite synchronously for a
clear prototype workflow. These processes demonstrate the intended service
boundary; they do not receive arbitrary URLs or execute uploaded code.
"""
import logging
import os
import signal
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
role = os.getenv("BAYORA_WORKER_ROLE", "restricted-worker")
logging.info("Bayora %s started with no outbound scan capability", role)
while running:
    time.sleep(5)
logging.info("Bayora %s stopped", role)

