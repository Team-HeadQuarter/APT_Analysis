import psutil
import yara
import os
import concurrent.futures
import logging
from datetime import datetime
import time


os.chdir(os.path.dirname(os.path.abspath(__file__)))


rule_path = "xzbotrule.txt"
rules = yara.compile(filepath=rule_path)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

EXCLUDE_NAMES = {"Xorg", "xfwm4", "code"}

def check_process_memory(pid):
    results = []
    try:
        logging.debug(f"Starting scan for PID {pid}")
        process = psutil.Process(pid)
        with process.oneshot():
            process_name = process.name()
            mem_maps = process.memory_maps()
            for mem_map in mem_maps:
                logging.debug(f"Reading memory map for PID {pid}, map: {mem_map.path}")
                try:
                    with open(mem_map.path, 'rb') as f:
                        data = f.read()
                        matches = rules.match(data=data)
                        if matches:
                            for match in matches:
                                result = f"PID {pid} (Process: {process_name}) matches rule '{match.rule}' with strings:\n"
                                for s in match.strings:
                                    result += f"  - {s}\n"
                                results.append(result)
                except (FileNotFoundError, PermissionError) as e:
                    logging.warning(f"Cannot read memory map for PID {pid}: {e}")
                    continue
                except Exception as e:
                    logging.error(f"Error reading memory map for PID {pid}: {e}")
                    continue  
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logging.warning(f"Cannot access process memory for PID {pid}: {e}")
    except Exception as e:
        logging.error(f"Error processing PID {pid}: {e}")
    logging.debug(f"Finished scan for PID {pid}")
    return results

def main():
    start_time = time.time()
    logging.info("Starting Yara memory scan")

    pids = [(proc.pid, proc.name()) for proc in psutil.process_iter() if proc.name() not in EXCLUDE_NAMES]
    logging.info(f"Found {len(pids)} processes to scan")

    all_results = []
    timeout = 60

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_pid = {executor.submit(check_process_memory, pid): (pid, name) for pid, name in pids}
        try:
            for future in concurrent.futures.as_completed(future_to_pid.keys(), timeout=timeout):
                pid, name = future_to_pid[future]
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                    logging.info(f"Completed scan for PID {pid} ({name})")
                except concurrent.futures.TimeoutError:
                    logging.warning(f"PID {pid} ({name}) took too long and was cancelled.")
                except Exception as e:
                    logging.error(f"PID {pid} ({name}) generated an exception: {e}")

                remaining_pids = [(future_to_pid[f][0], future_to_pid[f][1]) for f in future_to_pid.keys() if not f.done()]
                logging.info(f"Remaining processes to scan: {remaining_pids}")

        except concurrent.futures.TimeoutError:
            logging.warning(f"Overall timeout reached before all tasks completed.")

        for future in future_to_pid.keys():
            if not future.done():
                pid, name = future_to_pid[future]
                logging.warning(f"PID {pid} ({name}) did not complete in time and was cancelled.")
                future.cancel()

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{current_time}.txt" if all_results else f"no_results_{current_time}.txt"

    with open(filename, "w") as f:
        if all_results:
            for result in all_results:
                f.write(result)
                f.write("\n")
        else:
            f.write("No results\n")

        end_time = time.time()
        total_time = end_time - start_time
        f.write(f"\nTotal scan time: {total_time:.2f} seconds\n")

    logging.info(f"Yara memory scan completed, results saved to {filename}")

if __name__ == "__main__":
    main()
