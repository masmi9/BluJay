// Executive Dashboard JavaScript

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeInteractivity();
});

// Initialize charts
function initializeCharts() {
    const visualizations = dashboardData.visualizations || [];
    
    visualizations.forEach((viz, index) => {
        const canvasId = `chart-${index}`;
        const canvas = document.getElementById(canvasId);
        
        if (canvas) {
            createChart(canvas, viz);
        }
    });
}

// Create individual chart
function createChart(canvas, vizData) {
    const ctx = canvas.getContext('2d');
    
    let chartConfig = {
        type: vizData.chart_type === 'donut' ? 'doughnut' : vizData.chart_type,
        data: {
            labels: vizData.data.labels || vizData.data.categories || [],
            datasets: [{
                data: vizData.data.values || vizData.data.counts || [],
                backgroundColor: vizData.data.colors || [
                    '#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6'
                ],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    };
    
    // Customize based on chart type
    if (vizData.chart_type === 'line') {
        chartConfig.options.scales = {
            y: {
                beginAtZero: true
            }
        };
    }
    
    if (vizData.chart_type === 'gauge') {
        // Convert gauge to doughnut with custom styling
        chartConfig.type = 'doughnut';
        chartConfig.data = {
            datasets: [{
                data: [vizData.data.score, 100 - vizData.data.score],
                backgroundColor: ['#27ae60', '#ecf0f1'],
                borderWidth: 0
            }]
        };
        chartConfig.options.cutout = '70%';
        chartConfig.options.plugins.legend.display = false;
    }
    
    new Chart(ctx, chartConfig);
}

// Initialize interactivity
function initializeInteractivity() {
    // Add click handlers for KPI cards
    const kpiCards = document.querySelectorAll('.kpi-card');
    kpiCards.forEach(card => {
        card.addEventListener('click', function() {
            const kpiName = this.querySelector('.kpi-name').textContent;
            showKPIDetails(kpiName);
        });
    });
    
    // Add hover effects
    addHoverEffects();
}

// Show KPI details
function showKPIDetails(kpiName) {
    const kpiData = dashboardData.kpi_metrics.find(kpi => kpi.name === kpiName);
    if (kpiData) {
        alert(`${kpiName}\n\nCurrent: ${kpiData.value} ${kpiData.unit}\nTarget: ${kpiData.target} ${kpiData.unit}\nStatus: ${kpiData.status}\nTrend: ${kpiData.trend}`);
    }
}

// Add hover effects
function addHoverEffects() {
    const cards = document.querySelectorAll('.kpi-card, .viz-card, .compliance-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = '0 15px 35px rgba(0,0,0,0.1)';
            this.style.transition = 'all 0.3s ease';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 5px 15px rgba(0,0,0,0.05)';
        });
    });
}

// Export dashboard
function exportDashboard() {
    window.print();
}

// Refresh dashboard data
function refreshDashboard() {
    location.reload();
}
