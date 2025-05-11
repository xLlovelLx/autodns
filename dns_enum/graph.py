import networkx as nx
import matplotlib
matplotlib.use("Agg")  # Use a non-interactive backend for matplotlib
import matplotlib.pyplot as plt

def visualize_dns_graph(data, output_file=None):
    """
    Visualize DNS relationships as a graph.
    
    Args:
        data (dict): DNS data with relationships (e.g., subdomains, records).
        output_file (str): Path to save the graph image (optional).
    """
    graph = nx.DiGraph()

    for record_type, records in data.items():
        if records is None:
            continue
        for record in records:
            graph.add_edge(record_type, record)

    plt.figure(figsize=(10, 8))
    nx.draw(graph, with_labels=True, node_color="lightblue", font_size=10, font_weight="bold")
    if output_file:
        plt.savefig(output_file)
        print(f"Graph saved to {output_file}")
    else:
        plt.show()