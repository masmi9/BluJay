// AODS Interactive Report JavaScript

// Global variables
let filteredVulnerabilities = vulnerabilityData;
let currentSort = { field: 'severity', direction: 'desc' };

// Initialize report
document.addEventListener('DOMContentLoaded', function() {
    initializeFilters();
    initializeSorting();
    updateVulnerabilityDisplay();
});

// Toggle vulnerability details
function toggleVulnerability(index) {
    const content = document.getElementById(`vuln-content-${index}`);
    const icon = content.parentElement.querySelector('.toggle-icon');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.textContent = '▲';
    } else {
        content.style.display = 'none';
        icon.textContent = '▼';
    }
}

// Toggle evidence collection
function toggleEvidence(index) {
    const content = document.getElementById(`evidence-content-${index}`);
    const toggle = document.getElementById(`evidence-toggle-${index}`);
    
    if (content && toggle) {
        if (content.style.display === 'none') {
            content.style.display = 'block';
            toggle.textContent = '▲';
        } else {
            content.style.display = 'none';
            toggle.textContent = '▼';
        }
    }
}

// Toggle individual evidence item
function toggleEvidenceItem(vulnIndex, itemIndex) {
    const content = document.getElementById(`evidence-item-content-${vulnIndex}-${itemIndex}`);
    const toggle = document.getElementById(`evidence-item-toggle-${vulnIndex}-${itemIndex}`);
    
    if (content && toggle) {
        if (content.style.display === 'none') {
            content.style.display = 'block';
            toggle.textContent = '▼';
        } else {
            content.style.display = 'none';
            toggle.textContent = '▶';
        }
    }
}

// Toggle risk intelligence section
function toggleRiskIntelligence(vulnId) {
    const content = document.getElementById(`risk-content-${vulnId}`);
    const toggle = document.getElementById(`risk-toggle-${vulnId}`);
    
    if (content && toggle) {
        if (content.style.display === 'none') {
            content.style.display = 'block';
            toggle.textContent = '▲';
        } else {
            content.style.display = 'none';
            toggle.textContent = '▼';
        }
    }
}

// Initialize filter controls
function initializeFilters() {
    // Severity filter
    const severityFilter = document.getElementById('severityFilter');
    if (severityFilter) {
        severityFilter.addEventListener('change', applyFilters);
    }
    
    // Category filter
    const categoryFilter = document.getElementById('categoryFilter');
    if (categoryFilter) {
        categoryFilter.addEventListener('change', applyFilters);
    }
    
    // Search filter
    const searchFilter = document.getElementById('searchFilter');
    if (searchFilter) {
        searchFilter.addEventListener('input', applyFilters);
    }
}

// Apply filters - uses data-severity / data-category attributes on DOM items
function applyFilters() {
    const severityFilter = document.getElementById('severityFilter')?.value || 'all';
    const categoryFilter = document.getElementById('categoryFilter')?.value || 'all';
    const searchTerm = document.getElementById('searchFilter')?.value.toLowerCase() || '';

    const allItems = document.querySelectorAll('.vulnerability-item');
    let visibleCount = 0;

    allItems.forEach(item => {
        const itemSeverity = item.getAttribute('data-severity') || '';
        const itemCategory = item.getAttribute('data-category') || '';
        const itemText = item.textContent.toLowerCase();

        let visible = true;

        // Severity filter - compare lowercase to handle case differences
        if (severityFilter !== 'all' && itemSeverity.toLowerCase() !== severityFilter.toLowerCase()) {
            visible = false;
        }

        // Category filter
        if (categoryFilter !== 'all' && itemCategory !== categoryFilter) {
            visible = false;
        }

        // Search filter - match against all visible text in the item
        if (searchTerm && !itemText.includes(searchTerm)) {
            visible = false;
        }

        item.style.display = visible ? 'block' : 'none';
        if (visible) visibleCount++;
    });

    // Also keep the JS array in sync for sorting and export
    filteredVulnerabilities = vulnerabilityData.filter(vuln => {
        if (severityFilter !== 'all' && (vuln.severity || '').toLowerCase() !== severityFilter.toLowerCase()) return false;
        if (categoryFilter !== 'all' && vuln.category !== categoryFilter) return false;
        if (searchTerm && !(vuln.title || '').toLowerCase().includes(searchTerm) &&
            !(vuln.description || '').toLowerCase().includes(searchTerm)) return false;
        return true;
    });

    // Update count display
    const countElement = document.getElementById('vulnerabilityCount');
    if (countElement) {
        countElement.textContent = `${visibleCount} vulnerabilities`;
    }
}

// Initialize sorting
function initializeSorting() {
    const sortButtons = document.querySelectorAll('.sort-btn');
    sortButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const field = this.dataset.field;
            sortVulnerabilities(field);
        });
    });
}

// Sort vulnerabilities
function sortVulnerabilities(field) {
    if (currentSort.field === field) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.field = field;
        currentSort.direction = 'desc';
    }
    
    filteredVulnerabilities.sort((a, b) => {
        let valueA = a[field];
        let valueB = b[field];
        
        // Handle severity sorting (normalize to lowercase for lookup)
        if (field === 'severity') {
            const severityOrder = { 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'informational': 1 };
            valueA = severityOrder[(valueA || '').toLowerCase()] || 0;
            valueB = severityOrder[(valueB || '').toLowerCase()] || 0;
        }
        
        // Handle confidence sorting
        if (field === 'confidence') {
            valueA = parseFloat(valueA) || 0;
            valueB = parseFloat(valueB) || 0;
        }
        
        if (currentSort.direction === 'asc') {
            return valueA > valueB ? 1 : -1;
        } else {
            return valueA < valueB ? 1 : -1;
        }
    });
    
    updateVulnerabilityDisplay();
}

// Update vulnerability display - reorder DOM to match sorted array, then re-filter
function updateVulnerabilityDisplay() {
    const container = document.getElementById('vulnerabilityList');
    if (!container) return;

    const items = Array.from(container.querySelectorAll('.vulnerability-item'));
    if (items.length === 0) return;

    // Build a lookup from title to DOM element
    const itemsByTitle = new Map();
    items.forEach(el => {
        const title = el.getAttribute('data-title') || el.querySelector('h3')?.textContent?.trim() || '';
        itemsByTitle.set(title, el);
    });

    // Reorder DOM elements to match filteredVulnerabilities order
    filteredVulnerabilities.forEach(vuln => {
        const el = itemsByTitle.get(vuln.title);
        if (el) container.appendChild(el);
    });

    // Re-apply the current filters to ensure visibility matches state
    applyFilters();

    // Update sort button indicators
    document.querySelectorAll('.sort-btn').forEach(btn => {
        btn.classList.remove('sort-asc', 'sort-desc');
        if (btn.dataset.field === currentSort.field) {
            btn.classList.add('sort-' + currentSort.direction);
        }
    });
}

// Export functions
function exportToPDF() {
    // Simple PDF export using browser print
    window.print();
}

function exportToExcel() {
    // Convert vulnerability data to CSV format for Excel
    const csvData = convertToCSV(filteredVulnerabilities);
    downloadFile(csvData, 'aods-vulnerabilities.csv', 'text/csv');
}

function exportToCSV() {
    // Export filtered vulnerabilities as CSV
    const csvData = convertToCSV(filteredVulnerabilities);
    downloadFile(csvData, 'aods-vulnerabilities.csv', 'text/csv');
}

// Convert data to CSV format
function convertToCSV(data) {
    const headers = ['Title', 'Severity', 'Category', 'Confidence', 'Location', 'Description'];
    const csvRows = [headers.join(',')];
    
    data.forEach(vuln => {
        const row = [
            `"${vuln.title || ''}"`,
            `"${vuln.severity || ''}"`,
            `"${vuln.category || ''}"`,
            `"${vuln.confidence || ''}"`,
            `"${vuln.location || ''}"`,
            `"${(vuln.description || '').replace(/"/g, '""')}"`
        ];
        csvRows.push(row.join(','));
    });
    
    return csvRows.join('\n');
}

// Download file helper
function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
}

// Expand/collapse all vulnerabilities
function expandAll() {
    const contents = document.querySelectorAll('.vulnerability-content');
    const icons = document.querySelectorAll('.toggle-icon');
    
    contents.forEach(content => content.style.display = 'block');
    icons.forEach(icon => icon.textContent = '▲');
}

function collapseAll() {
    const contents = document.querySelectorAll('.vulnerability-content');
    const icons = document.querySelectorAll('.toggle-icon');
    
    contents.forEach(content => content.style.display = 'none');
    icons.forEach(icon => icon.textContent = '▼');
}
