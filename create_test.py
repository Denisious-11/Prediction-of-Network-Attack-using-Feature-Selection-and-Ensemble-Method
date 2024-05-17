# import pandas as pd



# import pandas as pd

# my_dataframe = pd.read_csv("KDDCUP_Data/preprocessed_data.csv")

# # Separate features and labels
# my_dataframe_y = my_dataframe[['Attack']]
# my_dataframe_X = my_dataframe.drop(['Attack'], axis=1)

# # Create a new DataFrame to store the selected rows
# selected_rows = pd.DataFrame()

# # Iterate through unique values in the "Attack" column
# for attack_value in range(5):  # Assuming Attack column has values 0, 1, 2, 3, 4
#     # Get 50 rows for each attack_value
#     subset = my_dataframe_X[my_dataframe_y['Attack'] == attack_value].head(50)
    
#     # Append the subset to the selected_rows DataFrame
#     selected_rows = selected_rows.append(subset, ignore_index=True)

# # Save the result to a 'test.csv' file
# selected_rows.to_csv('test.csv', index=False)


##################
import pandas as pd

my_dataframe = pd.read_csv("KDDCUP_Data/preprocessed_data.csv")

# Separate features and labels
my_dataframe_y = my_dataframe[['Attack']]
my_dataframe_X = my_dataframe.drop(['Attack'], axis=1)

# Create a new DataFrame to store the selected rows
selected_rows = pd.DataFrame()

# Iterate through unique values in the "Attack" column
for attack_value in range(5):  # Assuming Attack column has values 0, 1, 2, 3, 4
    # Get 50 rows for each attack_value
    subset = my_dataframe[my_dataframe_y['Attack'] == attack_value].head(50)
    
    # Append the subset to the selected_rows DataFrame
    selected_rows = selected_rows.append(subset, ignore_index=True)

# Save the result to a 'test.csv' file
selected_rows.to_csv('test_final.csv', index=False)
