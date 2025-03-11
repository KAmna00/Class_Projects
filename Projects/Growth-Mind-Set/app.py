from fileinput import fileno
import streamlit as st
import pandas as pd
from io import BytesIO

# Set page config FIRST
st.set_page_config(page_title="File Converter", layout="wide")

# Custom CSS to add a border around the entire app
st.markdown(
    """
    <style>
    /* Add a border around the entire app */
    .stApp {
        border: 5px solid #4CAF50;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.2);
        animation: fadeIn 1s ease-in-out;
    }

    /* Fade-in animation */
    @keyframes fadeIn {
        from {
            opacity: 0;
        }
        to {
            opacity: 1;
        }
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Page title and description
st.title("📁 File Converter & Cleaner")
st.write("Upload CSV or Excel files, clean data, and convert formats.")

# File uploader
files = st.file_uploader("Upload CSV or Excel Files", type=["csv", "xlsx"], accept_multiple_files=True)

if files:
    for file in files:
        ext = file.name.split(".")[-1]
        df = pd.read_csv(file) if ext == "csv" else pd.read_excel(file)

        st.subheader(f"📄 {file.name} - Preview")
        st.dataframe(df.head())

        if st.checkbox(f"Remove Duplicates - {file.name}"):
            df = df.drop_duplicates()
            st.success("✅ Duplicates Removed")
            st.dataframe(df.head())

            if st.checkbox(f"Fill Missing Values - {file.name}"):
                df.fillna(df.select_dtypes(include=["number"]).mean(), inplace=True)
                st.success("✅ Missing Values filled with mean")
                st.dataframe(df.head())

            selected_columns = st.multiselect(f"Select Columns - {file.name}", df.columns, default=df.columns)
            df = df[selected_columns]
            st.dataframe(df.head())

            if st.checkbox(f"Show Chart - {file.name}") and not df.select_dtypes(include="number").empty:
                st.bar_chart(df.select_dtypes(include="number").iloc[:, :2])

            format_choice = st.radio(f"Convert {file.name} to:", ["csv", "Excel"], key=file.name)

            if st.button(f"Download {file.name} as {format_choice}"):
                with st.spinner(f"⏳ Processing {file.name}..."):
                    output = BytesIO()
                    if format_choice == "csv":
                        df.to_csv(output, index=False)
                        mime = "text/csv"
                        new_name = file.name.replace(ext, "csv")
                    else:
                        df.to_excel(output, index=False, engine='openpyxl')
                        mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        new_name = file.name.replace(ext, "xlsx")

                    output.seek(0)
                    st.download_button("📥 Download file", file_name=new_name, data=output, mime=mime)
                    st.success("🎉 Processing Complete!")