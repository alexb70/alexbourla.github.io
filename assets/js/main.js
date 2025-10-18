// Wrap everything in an IIFE to prevent global variable conflicts
(function () {
    'use strict';

    // Mobile Navigation Toggle
    document.addEventListener('DOMContentLoaded', function () {
        const navToggle = document.getElementById('nav-toggle');
        const navMenu = document.getElementById('nav-menu');
        const navClose = document.getElementById('nav-close');

        if (navToggle && navMenu) {
            navToggle.addEventListener('click', function (e) {
                e.stopPropagation(); // Prevent event bubbling
                navMenu.classList.toggle('active');
            });
        }

        if (navClose && navMenu) {
            navClose.addEventListener('click', function (e) {
                e.stopPropagation(); // Prevent event bubbling
                navMenu.classList.remove('active');
            });
        }

        // Close mobile menu when clicking on a link
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (navMenu) {
                    navMenu.classList.remove('active');
                }
            });
        });

        // Close mobile menu when clicking outside
        document.addEventListener('click', function (event) {
            if (navMenu && navMenu.classList.contains('active')) {
                const isClickInsideNav = navMenu.contains(event.target) || navToggle.contains(event.target);

                if (!isClickInsideNav) {
                    navMenu.classList.remove('active');
                }
            }
        });

        // Close mobile menu when pressing Escape key
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' && navMenu && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
            }
        });
    });

    // Smooth scrolling for anchor links
    document.addEventListener('DOMContentLoaded', function () {
        const links = document.querySelectorAll('a[href^="#"]');

        links.forEach(link => {
            link.addEventListener('click', function (e) {
                e.preventDefault();

                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);

                if (targetElement) {
                    const offsetTop = targetElement.offsetTop - 80; // Account for fixed navbar

                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            });
        });
    });

    // Navbar background on scroll
    window.addEventListener('scroll', function () {
        const navbar = document.querySelector('.navbar');

        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    // Intersection Observer for animations
    document.addEventListener('DOMContentLoaded', function () {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver(function (entries) {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in-up');
                }
            });
        }, observerOptions);

        // Observe elements for animation
        const animatedElements = document.querySelectorAll('.service-card, .experience-item, .research-card');

        animatedElements.forEach(el => {
            observer.observe(el);
        });
    });

    // Typing effect for hero title
    function typeWriter(element, text, speed = 100) {
        let i = 0;
        element.innerHTML = '';

        function type() {
            if (i < text.length) {
                element.innerHTML += text.charAt(i);
                i++;
                setTimeout(type, speed);
            }
        }

        type();
    }

    // Initialize typing effect when page loads
    document.addEventListener('DOMContentLoaded', function () {
        const heroTitle = document.querySelector('.hero-title');

        if (heroTitle) {
            const originalText = heroTitle.textContent;
            typeWriter(heroTitle, originalText, 50);
        }
    });

    // Parallax effect for hero section
    window.addEventListener('scroll', function () {
        const scrolled = window.pageYOffset;
        const hero = document.querySelector('.hero');

        if (hero) {
            const rate = scrolled * -0.5;
            hero.style.transform = `translateY(${rate}px)`;
        }
    });



    // Form validation and submission for contact form
    document.addEventListener('DOMContentLoaded', function () {
        const contactForm = document.querySelector('#contact-form');

        if (contactForm) {
            contactForm.addEventListener('submit', function (e) {
                // Basic validation
                const name = document.getElementById('name').value;
                const email = document.getElementById('email').value;
                const subject = document.getElementById('subject').value;
                const message = document.getElementById('message').value;

                if (!name || !email || !subject || !message) {
                    e.preventDefault();
                    showNotification('Please fill in all fields', 'error');
                    return;
                }

                if (!isValidEmail(email)) {
                    e.preventDefault();
                    showNotification('Please enter a valid email address', 'error');
                    return;
                }

                // Form will submit normally to Formspree
                // No loading state - just let it work as intended
            });
        }
    });

    // Show notification function
    function showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? '#e74c3c' : 'var(--primary-color)'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: var(--radius-md);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        max-width: 300px;
    `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 4000);
    }

    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }



    // Add slideIn and slideOut animations
    const slideInStyle = document.createElement('style');
    slideInStyle.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;

    document.head.appendChild(slideInStyle);

    // Back to top functionality
    document.addEventListener('DOMContentLoaded', function () {
        const backToTopButton = document.getElementById('back-to-top');

        if (backToTopButton) {
            // Show/hide button based on scroll position
            window.addEventListener('scroll', function () {
                if (window.pageYOffset > 300) {
                    backToTopButton.classList.add('visible');
                } else {
                    backToTopButton.classList.remove('visible');
                }
            });

            // Smooth scroll to top when clicked
            backToTopButton.addEventListener('click', function () {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
        }
    });

})(); // End of IIFE