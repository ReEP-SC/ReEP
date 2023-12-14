# Experimental Results Data

This directory primarily includes the experimental results of ReEP compared with 8 mainstream tools, along with the raw data from different tools' experiments.

- `RQ1`: **_How does ReEP improve the Reentrancy detection precision of the Origin Tools?_**
   We conducted comparative experiments between ReEP and 8 state-of-the-art detection tools, analyzing the performance of ReEP in improving detection precision. The raw data for different tools is available in the `Origin_tools_output` folder, with each tool's statistical results saved in the respective CSV file.

- `RQ2`: **_What is the impact of ReEP on the recall rate?_**
   Comparative experiments between ReEP and 8 mainstream detection tools were performed to analyze the impact of ReEP on the recall rate. The raw data for different tools is available in the `Origin_tools_output` folder, with each tool's statistical results saved in the respective CSV file.

- `RQ3`: **_What is the extensibility of ReEP when merging multiple tools?_**
    ReEP's extensibility was evaluated by combining various sets of Origin Tools, with results categorized into Best_combo (highest precision), Worst_combo (lowest precision), and Random_combo (random combinations). The analysis includes ReEP combined with 2, 4, 6, and 8 tools.

- `RQ4`: **_What is the impact of different stages within ReEP?_**
   Analysis of the impact of different stages on the overall performance. Includes the results of ablation experiments on the effectiveness of each stage of ReEP.