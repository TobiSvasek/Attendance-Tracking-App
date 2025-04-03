document.addEventListener('DOMContentLoaded', function() {
    const themeToggleButton = document.querySelector('#theme-toggle-button');
    const body = document.body;

    themeToggleButton.addEventListener('click', function() {
        if (body.classList.contains('light')) {
            body.classList.remove('light');
            body.classList.add('dark');
            themeToggleButton.innerHTML = '🌙'; // Moon icon for dark mode
        } else {
            body.classList.remove('dark');
            body.classList.add('light');
            themeToggleButton.innerHTML = '☀️'; // Sun icon for light mode
        }
    });
});