import pandas as pd
import matplotlib.pyplot as plt

# Construct the DataFrame with the provided benchmarking data (in ms)
data = {
    'n': [10, 20, 40, 80],
    'Setup_mean': [154.034, 311.528, 622.079, 1436.917],
    'Setup_stddev': [149.554, 332.687, 458.327, 1072.635],
    'Sharing_mean': [140.697, 194.402, 680.538, 2065.080],
    'Sharing_stddev': [102.309, 148.899, 338.389, 606.580 ],
    'Verification_mean': [1046.885, 2032.903, 13512.893, 75678.550],
    'Verification_stddev': [190.663, 445.612, 749.090, 7730.025],
    'Threshold_mean': [320.139, 430.186, 1455.428, 4437.709],
    'Threshold_stddev': [152.322, 178.199, 324.257, 214.449 ],
    'Total_mean': [1803.569, 3169.502, 17146.555, 84302.053 ],
    'Total_stddev': [788.393, 1347.448, 1810.168, 7512.103]
}
df = pd.DataFrame(data)

# Convert times from milliseconds to seconds
time_cols = [col for col in df.columns if col != 'n']
df[time_cols] = df[time_cols] / 1000.0

# Plot curves with error bars for each phase, in seconds
plt.figure(figsize=(12, 7))

phases = ['Setup', 'Sharing', 'Verification', 'Threshold', 'Total']
for phase in phases:
    plt.errorbar(
        df['n'],
        df[f'{phase}_mean'],
        yerr=df[f'{phase}_stddev'],
        fmt='-o',
        capsize=4,
        markersize=8,
        label=phase
    )

plt.title("NAP-DKG Benchmark Scaling Curve")
plt.xlabel("Number of Parties (n)")
plt.ylabel("Time (s)")
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
