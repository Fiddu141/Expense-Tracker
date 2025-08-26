import streamlit as st
import os
import json
from datetime import datetime
import re

# Page configuration
st.set_page_config(
    page_title="Book Search App",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .upload-section {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        margin: 1rem 0;
    }
    .search-section {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        margin: 1rem 0;
    }
    .book-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin: 1rem 0;
        border-left: 5px solid #1f77b4;
    }
    .search-result {
        background: white;
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        margin: 1rem 0;
        border-left: 5px solid #f093fb;
    }
    .stButton > button {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.5rem 2rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .file-uploader {
        border: 2px dashed #667eea;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        background: rgba(255,255,255,0.1);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'books' not in st.session_state:
    st.session_state.books = []
if 'search_history' not in st.session_state:
    st.session_state.search_history = []

# Load books from file if exists
def load_books():
    if os.path.exists('books.json'):
        try:
            with open('books.json', 'r') as f:
                st.session_state.books = json.load(f)
        except:
            st.session_state.books = []

# Save books to file
def save_books():
    with open('books.json', 'w') as f:
        json.dump(st.session_state.books, f)

# Load books on startup
load_books()

# Main header
st.markdown('<h1 class="main-header">📚 Book Search App</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("📖 Navigation")
    page = st.selectbox(
        "Choose a page:",
        ["🏠 Home", "📤 Upload Books", "🔍 Search Books", "📚 My Library", "📊 Search History"]
    )

# Home page
if page == "🏠 Home":
    st.markdown("""
    <div style="text-align: center; padding: 2rem;">
        <h2>Welcome to Book Search App!</h2>
        <p style="font-size: 1.2rem; color: #666;">
            Upload your books and search for definitions with our intelligent search system.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Books", len(st.session_state.books))
    
    with col2:
        st.metric("Total Searches", len(st.session_state.search_history))
    
    with col3:
        if st.session_state.books:
            latest_book = max(st.session_state.books, key=lambda x: x['upload_date'])
            st.metric("Latest Upload", latest_book['title'][:20] + "..." if len(latest_book['title']) > 20 else latest_book['title'])

# Upload Books page
elif page == "📤 Upload Books":
    st.markdown('<div class="upload-section">', unsafe_allow_html=True)
    st.header("📤 Upload Your Books")
    st.write("Upload your books in PDF, TXT, or DOCX format to add them to your library.")
    st.markdown('</div>', unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Choose book files",
        type=['pdf', 'txt', 'docx'],
        accept_multiple_files=True,
        help="Upload multiple books at once"
    )
    
    if uploaded_files:
        for uploaded_file in uploaded_files:
            if st.button(f"Process {uploaded_file.name}", key=uploaded_file.name):
                # Extract text content (simplified for demo)
                if uploaded_file.type == "text/plain":
                    content = uploaded_file.read().decode("utf-8")
                else:
                    # For PDF and DOCX, we'll create a placeholder content
                    content = f"Content from {uploaded_file.name} - This is a sample text for demonstration purposes."
                
                # Create book entry
                book = {
                    'id': len(st.session_state.books) + 1,
                    'title': uploaded_file.name,
                    'content': content,
                    'file_type': uploaded_file.type,
                    'file_size': len(content),
                    'upload_date': datetime.now().isoformat(),
                    'keywords': extract_keywords(content)
                }
                
                st.session_state.books.append(book)
                save_books()
                st.success(f"✅ {uploaded_file.name} uploaded successfully!")
                st.rerun()

# Search Books page
elif page == "🔍 Search Books":
    st.markdown('<div class="search-section">', unsafe_allow_html=True)
    st.header("🔍 Search Your Books")
    st.write("Search for definitions, concepts, or any text within your uploaded books.")
    st.markdown('</div>', unsafe_allow_html=True)
    
    search_query = st.text_input(
        "Enter your search query:",
        placeholder="e.g., artificial intelligence, machine learning, neural networks..."
    )
    
    if search_query:
        if st.button("🔍 Search", type="primary"):
            search_results = search_books(search_query)
            st.session_state.search_history.append({
                'query': search_query,
                'timestamp': datetime.now().isoformat(),
                'results_count': len(search_results)
            })
            
            if search_results:
                st.markdown('<div class="search-result">', unsafe_allow_html=True)
                st.subheader(f"📖 Search Results for: '{search_query}'")
                
                # Generate generic answer
                generic_answer = generate_generic_answer(search_query, search_results)
                st.markdown(f"**🎯 Generic Answer:** {generic_answer}")
                
                st.markdown("---")
                st.subheader("📚 Found in these books:")
                
                for result in search_results:
                    with st.expander(f"📖 {result['book_title']} - {result['context'][:100]}..."):
                        st.write(f"**Context:** {result['context']}")
                        st.write(f"**Relevance Score:** {result['relevance']:.2f}")
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.warning("🔍 No results found for your search query.")

# My Library page
elif page == "📚 My Library":
    st.header("📚 My Book Library")
    
    if not st.session_state.books:
        st.info("📚 No books uploaded yet. Go to the Upload Books page to add some books!")
    else:
        for book in st.session_state.books:
            with st.expander(f"📖 {book['title']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**File Type:** {book['file_type']}")
                    st.write(f"**Upload Date:** {book['upload_date'][:10]}")
                    st.write(f"**Content Preview:** {book['content'][:200]}...")
                with col2:
                    if st.button("🗑️ Delete", key=f"del_{book['id']}"):
                        st.session_state.books = [b for b in st.session_state.books if b['id'] != book['id']]
                        save_books()
                        st.success("Book deleted successfully!")
                        st.rerun()

# Search History page
elif page == "📊 Search History":
    st.header("📊 Search History")
    
    if not st.session_state.search_history:
        st.info("🔍 No search history yet. Start searching to see your history!")
    else:
        for search in reversed(st.session_state.search_history):
            st.write(f"**Query:** {search['query']}")
            st.write(f"**Date:** {search['timestamp'][:19]}")
            st.write(f"**Results:** {search['results_count']}")
            st.markdown("---")

# Helper functions
def extract_keywords(content):
    """Extract keywords from content (simplified)"""
    words = re.findall(r'\b\w+\b', content.lower())
    # Remove common stop words
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
    keywords = [word for word in words if word not in stop_words and len(word) > 3]
    return list(set(keywords))[:20]

def search_books(query):
    """Search through uploaded books"""
    results = []
    query_lower = query.lower()
    
    for book in st.session_state.books:
        content_lower = book['content'].lower()
        if query_lower in content_lower:
            # Find context around the query
            start = max(0, content_lower.find(query_lower) - 100)
            end = min(len(book['content']), content_lower.find(query_lower) + len(query_lower) + 100)
            context = book['content'][start:end]
            
            # Calculate simple relevance score
            relevance = content_lower.count(query_lower) / len(content_lower.split())
            
            results.append({
                'book_title': book['title'],
                'context': context,
                'relevance': relevance
            })
    
    # Sort by relevance
    results.sort(key=lambda x: x['relevance'], reverse=True)
    return results

def generate_generic_answer(query, results):
    """Generate a generic answer based on search results"""
    if not results:
        return f"I couldn't find any specific information about '{query}' in your uploaded books."
    
    # Simple generic answer generation
    book_count = len(set(result['book_title'] for result in results))
    total_occurrences = sum(result['relevance'] for result in results)
    
    if book_count == 1:
        return f"Based on your search for '{query}', I found relevant information in 1 book with {total_occurrences:.1f} occurrences. The content appears to be related to your query and can be found in the search results below."
    else:
        return f"Based on your search for '{query}', I found relevant information across {book_count} books with {total_occurrences:.1f} total occurrences. The content appears to be related to your query and can be found in the search results below."

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666; padding: 1rem;'>"
    "📚 Book Search App - Upload, Search, and Discover Knowledge"
    "</div>",
    unsafe_allow_html=True
)