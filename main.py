# main.py
import sys
import signal # Import signal module

# Import the GUI starter function
from gui import run_gui 

# This signal handler is primarily for graceful exits when the GUI itself is closed
# or if Ctrl+C is pressed before the GUI fully launches.
# The GUI's start/stop buttons and its closing method handle the sniffer's lifecycle.
def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting SpoofSniff GUI gracefully...")
    # The GUI's stop_monitoring function (called by its buttons or window close event)
    # handles signalling the sniffer thread to stop and saving the cache.
    # This signal handler ensures the main Python process exits if Ctrl+C is used.
    sys.exit(0)

def main():
    # Register the signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print("Launching SpoofSniff GUI...")
    # All previous logic (cache loading, privilege checks, starting sniffer, etc.)
    # is now handled within the gui.py file when the GUI starts.
    # This call will block until the GUI window is closed.
    run_gui() 

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nAn unhandled error occurred in the main application loop: {e}")
        sys.exit(1)