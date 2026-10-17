import pytest
from app import allowed_file

@pytest.mark.parametrize("filename, expected", [
    # Valid extensions
    ("image.png", True),
    ("photo.jpg", True),
    ("picture.jpeg", True),
    ("animation.gif", True),

    # Uppercase extensions
    ("IMAGE.PNG", True),
    ("PHOTO.JPG", True),

    # Invalid extensions
    ("document.txt", False),
    ("script.py", False),
    ("archive.zip", False),
    ("executable.exe", False),

    # No extension
    ("filename", False),
    ("filename.", False),

    # Multiple dots
    ("archive.tar.gz", False),
    ("my.image.png", True),

    # Hidden files
    (".hidden", False),
    (".hidden.png", True),
])
def test_allowed_file(filename, expected):
    assert allowed_file(filename) == expected
