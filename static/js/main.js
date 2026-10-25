 const navConfigs = {
        admin: {
            title: "Admin Dashboard Overview",
            user: "Jharana Kunwar (Admin)",
            nav: [
                { icon: "fa-chart-line", label: "Dashboard Overview", active: true },
                { icon: "fa-bowl-food", label: "Manage Menu Items" },
                { icon: "fa-users", label: "Staff & User Roles" },
                { icon: "fa-chart-pie", label: "Sales Reports" },
                { icon: "fa-gear", label: "System Settings" }
            ]
        },
        cashier: {
            title: "Cashier & Digital Token Counter",
            user: "Cashier Counter #01",
            nav: [
                { icon: "fa-calculator", label: "Token Generation", active: true },
                { icon: "fa-clock-rotate-left", label: "Transaction History" },
                { icon: "fa-qrcode", label: "Verify Digital Token" }
            ]
        },
        kitchen: {
            title: "Kitchen Order Display System",
            user: "Kitchen Staff / Cook",
            nav: [
                { icon: "fa-fire", label: "Active Orders", active: true },
                { icon: "fa-circle-check", label: "Completed Orders" }
            ]
        }
    };

    function switchRole(role) {
        // Hide all views
        document.querySelectorAll('.view-section').forEach(view => view.classList.remove('active'));
        
        // Show selected view
        document.getElementById(`${role}-view`).classList.add('active');

        // Update Nav Menu and Titles
        const config = navConfigs[role];
        document.getElementById('roleTitle').innerText = config.title;
        document.getElementById('userName').innerText = config.user;

        const navContainer = document.getElementById('sidebarNav');
        navContainer.innerHTML = '';
        config.nav.forEach(item => {
            const li = document.createElement('li');
            if(item.active) li.classList.add('active');
            li.innerHTML = `<a href="#"><i class="fa-solid ${item.icon} me-2"></i>${item.label}</a>`;
            navContainer.appendChild(li);
        });
    }

    // Initialize Default Role
    document.addEventListener("DOMContentLoaded", () => {
        switchRole('admin');
    });
