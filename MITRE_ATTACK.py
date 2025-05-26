import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap

# ----------------------------------
# INSTALL MISSING DEPENDENCIES FIRST:
# Run these in PyCharm's terminal:
# pip install jinja2 openpyxl
# ----------------------------------

# Custom priority data
lazarus_ttps = [
    ("Initial Access", "T1589", "Gather Victim Identity", 4, "LinkedIn employee profiling"),
    ("Initial Access", "T1591", "Gather Org Info", 5, "Annual reports analysis"),
    ("Execution", "T1059", "Command-Line", 5, "PowerShell -EncodedCommand"),
    ("Persistence", "T1112", "Modify Registry", 5, "HKCU\\Run key modification"),
    ("Defense Evasion", "T1140", "Deobfuscate", 5, "Custom XOR unpacker"),
    ("Discovery", "T1083", "File Discovery", 2, "dir /s command"),
]

# Create DataFrame
df = pd.DataFrame(lazarus_ttps, columns=["Tactic", "TechID", "Technique", "Priority", "Example"])


# ----------------------------------
# 1. HEATMAP VISUALIZATION (WORKING)
# ----------------------------------
def generate_heatmap():
    plt.figure(figsize=(10, 6))
    colors = ["#FF0000", "#FF9999", "#FFFFFF", "#99FF99", "#00AA00"]
    cmap = LinearSegmentedColormap.from_list("lazarus_priority", colors, N=5)

    heatmap_data = df.pivot(
        index="Technique",
        columns="Tactic",
        values="Priority"
    )

    sns.heatmap(
        heatmap_data,
        cmap=cmap,
        vmin=0, vmax=5,
        annot=True,
        linewidths=0.5,
        cbar_kws={'label': 'Priority Level (0-5)'}
    )

    plt.title("Lazarus Group TTP Prioritization", pad=20)
    plt.tight_layout()
    plt.savefig("lazarus_priorities.png", dpi=300)
    plt.show()


# ----------------------------------
# 2. DETECTION RECOMMENDATIONS
# ----------------------------------
def get_detection_recommendations(tech_id):
    detection_rules = {
        "T1589": "Monitor LinkedIn profile views from unknown IPs",
        "T1112": "Alert on HKCU\\Run* registry changes",
        "T1059": "Detect base64-encoded PowerShell",
        "T1140": "YARA rules for XOR patterns"
    }
    return detection_rules.get(tech_id, "Generic EDR monitoring")


df["Detection"] = df["TechID"].apply(get_detection_recommendations)


# ----------------------------------
# 3. FIXED EXPORT FUNCTION
# ----------------------------------
def export_prioritized_ttps():
    try:
        # Simple CSV export as fallback
        df.to_csv("lazarus_ttp_analysis.csv", index=False)
        print("[+] CSV exported successfully")

        # Excel export with styling (requires jinja2/openpyxl)
        try:
            from openpyxl import Workbook
            writer = pd.ExcelWriter("lazarus_ttp_analysis.xlsx", engine='openpyxl')

            # Create at least one visible sheet
            wb = Workbook()
            wb.save("lazarus_ttp_analysis.xlsx")

            # Write data
            df.to_excel(writer, index=False, sheet_name='Lazarus_TTPs')
            writer.close()
            print("[+] Excel exported with styling")

        except Exception as e:
            print(f"[!] Excel export failed: {str(e)}")
            print("[+] Using CSV instead")

    except Exception as e:
        print(f"[!] Export failed completely: {str(e)}")


# ----------------------------------
# EXECUTE ANALYSIS
# ----------------------------------
if __name__ == "__main__":
    print("\n=== Lazarus Group TTP Analysis ===")
    print(df[["TechID", "Technique", "Priority"]])

    generate_heatmap()
    export_prioritized_ttps()

    print("\nExample detection for T1112:")
    print(get_detection_recommendations("T1112"))