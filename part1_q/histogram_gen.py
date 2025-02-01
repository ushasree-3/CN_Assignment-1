import matplotlib.pyplot as plt
import csv

# Initialize lists to store data
sizes = []
frequencies = []

# Read the CSV file containing histogram data
with open('histogram_data.csv', 'r') as file:
    reader = csv.reader(file)
    for row in reader:
        size = int(row[0])  # Packet size
        freq = int(row[1])  # Frequency
        sizes.append(size)
        frequencies.append(freq)

# Plot the histogram
plt.bar(sizes, frequencies, width=20, align='center', color='red')
plt.xlabel('Packet Size (bytes)')
plt.ylabel('Frequency')
plt.title('Packet Size Distribution')
plt.grid(True, axis='y')

# Save the plot as an image
plt.savefig('results/packet_sizes_distribution.png')
plt.close()
