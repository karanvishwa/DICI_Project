import pandas as pd

BASE = "G:/DICI_react/dici_backend/scripts/raw"  # Adjust this path as needed


files = [
        f"{BASE}/australia_data/ip_1.csv",
        f"{BASE}/australia_data/ip_2.csv",
        f"{BASE}/australia_data/ip_3.csv",
        f"{BASE}/australia_data/ip_4.csv"
]

mapping = {
    'srcip':'src_ip',
    'dstip':'dest_ip',
    'sport':'src_port',
    'dsport':'dest_port',
    'proto':'protocol',
    'dur':'duration',
    'Label':'label'
}

dfs = []

for f in files:
    df = pd.read_csv(f, low_memory=False)
    
    # 🔥 CRITICAL FIX
    df.columns = df.columns.str.strip()
    
    dfs.append(df)

cols = list(mapping.keys())

final_df = pd.concat(
    [df[cols] for df in dfs],
    ignore_index=True
)

final_df = final_df.rename(columns=mapping)

final_df['protocol'] = final_df['protocol'].astype('category').cat.codes

# 1. Define the columns you want to convert (exclude IPs)
numeric_cols = ['src_port', 'dest_port', 'duration', 'label']

for col in numeric_cols:
    # pd.to_numeric forces strings to numbers
    # errors='coerce' turns un-convertible text (like "unknown") into NaN
    final_df[col] = pd.to_numeric(final_df[col], errors='coerce')
    
    # 2. Fill NaN values that resulted from the conversion (e.g., set them to 0)
    final_df[col] = final_df[col].fillna(0)
    
    # 3. Optional: Convert to specific type (int or float)
    # If it's a label or port, int is usually better
    if col in ['src_port', 'dest_port', 'label']:
        final_df[col] = final_df[col].astype(int)
    else:
        final_df[col] = final_df[col].astype(float)


final_df.to_csv(f"{BASE}/australia_combined_data.csv", index=False)