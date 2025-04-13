from concurrent.futures import ThreadPoolExecutor

def execute_with_threads(task_function, task_args_list, max_threads=10, verbose=False):
    """
    Execute a task function with multiple arguments using threading.

    Args:
        task_function (function): The function to execute.
        task_args_list (list): A list of arguments for the task function.
        max_threads (int): Maximum number of threads to use.
        verbose (bool): Enable verbose mode.

    Returns:
        list: A list of results from the task function.
    """
    results = []
    if verbose:
        print(f"Executing tasks with {max_threads} threads...")

    def wrapper(args):
        return task_function(*args)

    with ThreadPoolExecutor(max_threads) as executor:
        future_tasks = [executor.submit(wrapper, args) for args in task_args_list]
        for future in future_tasks:
            try:
                results.append(future.result())
            except Exception as e:
                if verbose:
                    print(f"Error in threaded execution: {e}")

    return results