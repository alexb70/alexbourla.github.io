// Research page functionality
document.addEventListener('DOMContentLoaded', function () {
    // Generate table of contents
    generateTOC();

    // Calculate reading time
    calculateReadingTime();

    // Setup smooth scrolling for TOC links
    setupSmoothScrolling();

    // Setup copy link functionality
    setupCopyLink();

    // Setup active section highlighting
    setupActiveSectionHighlighting();
});

function generateTOC() {
    const tocNav = document.getElementById('toc-nav');
    const headings = document.querySelectorAll('.research-body h2, .research-body h3, .research-body h4');

    if (headings.length === 0) {
        tocNav.innerHTML = '<p class="toc-empty">No headings found</p>';
        return;
    }

    // Find the Vulnerability Summary section (second h2)
    const vulnerabilitySummaryHeading = Array.from(headings).find(heading =>
        heading.tagName === 'H2' && heading.textContent.includes('Vulnerability Summary')
    );

    if (!vulnerabilitySummaryHeading) {
        tocNav.innerHTML = '<p class="toc-empty">No Vulnerability Summary section found</p>';
        return;
    }

    // Create TOC HTML - only include headings after Vulnerability Summary
    let tocHTML = '<ul class="toc-list">';
    let currentLevel = 2;
    let includeHeading = false;

    headings.forEach((heading, index) => {
        // Start including headings after Vulnerability Summary
        if (heading === vulnerabilitySummaryHeading) {
            includeHeading = true;
            return; // Skip the Vulnerability Summary heading itself
        }

        if (!includeHeading) return;

        const level = parseInt(heading.tagName.charAt(1));
        const id = `heading-${index}`;
        heading.id = id;

        // Close previous levels if current level is higher
        if (level > currentLevel) {
            for (let i = currentLevel; i < level; i++) {
                tocHTML += '<ul class="toc-sublist">';
            }
        } else if (level < currentLevel) {
            for (let i = currentLevel; i > level; i--) {
                tocHTML += '</ul>';
            }
        }

        tocHTML += `<li class="toc-item toc-level-${level}">
            <a href="#${id}" class="toc-link" data-target="${id}">${heading.textContent}</a>
        </li>`;

        currentLevel = level;
    });

    // Close any remaining open lists
    for (let i = currentLevel; i > 2; i--) {
        tocHTML += '</ul>';
    }

    tocHTML += '</ul>';
    tocNav.innerHTML = tocHTML;

    // Move the TOC section to appear after the Vulnerability Summary section
    const tocSection = document.getElementById('toc-section');

    // Find the end of the Vulnerability Summary section (next h2 or end of content)
    let nextSection = vulnerabilitySummaryHeading.nextElementSibling;
    while (nextSection && nextSection.tagName !== 'H2') {
        nextSection = nextSection.nextElementSibling;
    }

    if (nextSection) {
        // Insert TOC before the next section
        nextSection.parentNode.insertBefore(tocSection, nextSection);
    } else {
        // If no next section, append to the end of the research body
        const researchBody = document.querySelector('.research-body');
        researchBody.appendChild(tocSection);
    }
}

function calculateReadingTime() {
    const content = document.querySelector('.research-body');
    const text = content.textContent;
    const wordsPerMinute = 200; // Average reading speed
    const wordCount = text.split(/\s+/).length;
    const readingTime = Math.ceil(wordCount / wordsPerMinute);

    document.getElementById('reading-time').textContent = `${readingTime} min read`;
}

function setupSmoothScrolling() {
    const tocLinks = document.querySelectorAll('.toc-link');

    tocLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);

            if (targetElement) {
                const offsetTop = targetElement.offsetTop - 100; // Account for fixed navbar
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });
}


function setupCopyLink() {
    const copyBtn = document.getElementById('copy-link-btn');

    copyBtn.addEventListener('click', function () {
        const url = window.location.href;

        if (navigator.clipboard) {
            navigator.clipboard.writeText(url).then(() => {
                showCopyFeedback(this);
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = url;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            showCopyFeedback(this);
        }
    });
}

function showCopyFeedback(button) {
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
    button.classList.add('copied');

    setTimeout(() => {
        button.innerHTML = originalText;
        button.classList.remove('copied');
    }, 2000);
}

function setupActiveSectionHighlighting() {
    const tocLinks = document.querySelectorAll('.toc-link');
    const headings = document.querySelectorAll('.research-body h2, .research-body h3, .research-body h4');

    function updateActiveSection() {
        let currentSection = '';

        headings.forEach(heading => {
            const rect = heading.getBoundingClientRect();
            if (rect.top <= 150) { // 150px offset for navbar
                currentSection = heading.id;
            }
        });

        // Update active states
        tocLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-target') === currentSection) {
                link.classList.add('active');
            }
        });
    }

    window.addEventListener('scroll', updateActiveSection);
    updateActiveSection(); // Initial call
}
