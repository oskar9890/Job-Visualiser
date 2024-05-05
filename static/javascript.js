function signUp() {
    document.getElementById("login-main").style.display="none";
    document.getElementById("signup-main").style.display="flex";
  }
  
  function login() {
    document.getElementById("login-main").style.display="flex";
    document.getElementById("signup-main").style.display="none";
  }
  


  document.addEventListener('DOMContentLoaded', function() {
    var duration = 2500; 
    var successMessage = document.getElementById('successMessage');

    if (successMessage) {
        setTimeout(function() {
            successMessage.style.display = 'none';
        }, duration);
    }
});

//make canvas full screen
document.addEventListener('DOMContentLoaded', function() {
  const canvases = document.querySelectorAll('.canvas-keywords');

  function toggleFullScreen(element) {
      if (!document.fullscreenElement) {
          element.requestFullscreen().catch(err => {
              console.log(`Error: ${err.message}`);
          });
      } else {
          document.exitFullscreen();
      }
  }

// event listener for full screen
  canvases.forEach(canvas => {
      canvas.addEventListener('click', function() {
          toggleFullScreen(canvas);
      });
  });
});


//fade in homepage content on scroll
function fadeInSection() {
    const sections = document.querySelectorAll('.section2-content');
    sections.forEach(section => {
        const sectionTop = section.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        if (sectionTop < windowHeight) {
            section.classList.add('fade-in');
        }
    });
}

window.addEventListener('scroll', fadeInSection);