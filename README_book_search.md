# 📚 Book Search App

A modern web application built with Streamlit that allows you to upload books and search for definitions with intelligent search functionality.

## ✨ Features

- **📤 Book Upload**: Upload books in PDF, TXT, and DOCX formats
- **🔍 Smart Search**: Search through your uploaded books for any definition or concept
- **🎯 Generic Answers**: Get intelligent, generic responses based on your search queries
- **📚 Library Management**: Organize and manage your book collection
- **📊 Search History**: Track all your search queries and results
- **🎨 Modern UI**: Beautiful, responsive interface with gradient designs

## 🚀 Installation

1. **Clone or download the application files**
2. **Install dependencies**:
   ```bash
   pip install -r requirements_book_search.txt
   ```

## 🏃‍♂️ Running the App

1. **Navigate to the app directory**:
   ```bash
   cd /path/to/your/app
   ```

2. **Run the Streamlit app**:
   ```bash
   streamlit run book_search_app.py
   ```

3. **Open your browser** and go to the URL shown in the terminal (usually `http://localhost:8501`)

## 📖 How to Use

### 1. **Home Page** 🏠
- View overview statistics
- See total books and searches
- Quick access to all features

### 2. **Upload Books** 📤
- Click "Upload Books" in the sidebar
- Drag and drop or select book files
- Supported formats: PDF, TXT, DOCX
- Click "Process" to add books to your library

### 3. **Search Books** 🔍
- Navigate to "Search Books" page
- Enter your search query (e.g., "artificial intelligence", "machine learning")
- Click the search button
- Get a generic answer and detailed results

### 4. **My Library** 📚
- View all uploaded books
- See book details and content previews
- Delete books if needed

### 5. **Search History** 📊
- Track all your search queries
- View results count and timestamps

## 🔧 Technical Details

- **Framework**: Streamlit
- **File Storage**: Local JSON file (`books.json`)
- **Search Algorithm**: Simple text matching with relevance scoring
- **File Processing**: Basic text extraction for TXT files, placeholder for PDF/DOCX

## 📁 File Structure

```
book_search_app/
├── book_search_app.py          # Main application file
├── requirements_book_search.txt # Python dependencies
├── README_book_search.md       # This file
└── books.json                 # Book data storage (created automatically)
```

## 🎯 Search Features

- **Generic Answers**: The app provides intelligent, generic responses to your search queries
- **Context Display**: Shows relevant text snippets around your search terms
- **Relevance Scoring**: Results are ranked by relevance
- **Multi-book Search**: Search across all your uploaded books simultaneously

## 🚧 Limitations & Future Improvements

**Current Limitations:**
- PDF and DOCX processing is simplified (placeholder content)
- Basic text search without advanced NLP
- Local storage only

**Potential Improvements:**
- Full PDF/DOCX text extraction
- Advanced NLP and semantic search
- Cloud storage integration
- User authentication
- Collaborative libraries
- Advanced analytics

## 🐛 Troubleshooting

**Common Issues:**

1. **Port already in use**: Change the port with `streamlit run book_search_app.py --server.port 8502`
2. **File upload errors**: Ensure files are not corrupted and are in supported formats
3. **Search not working**: Make sure you have uploaded books first

## 📝 Example Usage

1. Upload a few books (TXT files work best for demo)
2. Search for terms like "technology", "science", "learning"
3. View the generic answers and detailed results
4. Explore your library and search history

## 🤝 Contributing

Feel free to enhance this application by:
- Improving the search algorithm
- Adding more file format support
- Enhancing the UI/UX
- Adding new features

## 📄 License

This project is open source and available under the MIT License.

---

**Happy Reading and Searching! 📚🔍**