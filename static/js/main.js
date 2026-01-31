function updateDate() {
    const dateContainer = document.getElementById('live-date');
    const now = new Date();
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    
    // Add some random flair or location
    const locations = ["Sandarmokh"];
    const randomLocation = locations[Math.floor(Math.random() * locations.length)];
    
    dateContainer.innerText = `From ${randomLocation} • ${now.toLocaleDateString('en-US', options)}`;
}

document.addEventListener('DOMContentLoaded', () => {
    updateDate();
    
    // Randomly "shake" images occasionally to look like moving photos
    const images = document.querySelectorAll('.moving-picture');
    
    images.forEach(img => {
        setInterval(() => {
            if(Math.random() > 0.7) {
                img.style.transform = `rotate(${Math.random() * 2 - 1}deg) scale(${1 + Math.random() * 0.02})`;
                setTimeout(() => {
                    img.style.transform = 'rotate(0deg) scale(1)';
                }, 500);
            }
        }, 3000 + Math.random() * 5000);
    });
});
