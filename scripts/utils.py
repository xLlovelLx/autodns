import os

def validate_file_path(file_path, default_path):
    """
    Validate a file path; if invalid, return the default path.
    """
    if file_path is None:
        return default_path
    if file_path and os.path.exists(file_path):
        return os.path.normpath(file_path)
    else:
        print(f"Invalid or missing file path: {file_path}. Using default: {default_path}")
        return default_path

def load_file_lines(file_path):
    """
    Load lines from a file, stripping whitespace and skipping empty lines.
    """
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading file {file_path}: {e}")
        return []

def save_results_to_file(results, output_file):
    """
    Save results to a specified file in a readable format.
    """
    try:
        with open(output_file, "w") as f:
            for key, value in results.items():
                f.write(f"{key}: {', '.join(value)}\n")
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results to file: {e}")
        
def get_dynamic_max_workers(num_tasks):
    # For I/O-bound tasks, 5-10x CPU count is usually safe
    cpu_count = os.cpu_count() or 4
    max_threads = min(max(cpu_count * 10, 10), 200)  # between 10 and 200
    return min(max_threads, num_tasks)