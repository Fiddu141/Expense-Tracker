#!/bin/bash

echo "📚 Starting Book Search App..."
echo "Installing dependencies..."

# Install requirements
pip install -r requirements_book_search.txt

echo "🚀 Launching the application..."
echo "The app will open in your browser at http://localhost:8501"
echo "Press Ctrl+C to stop the application"

# Run the Streamlit app
streamlit run book_search_app.py