// Global utility functions

// Format NIK input (only numbers, max 16 digits)
function formatNIK(input) {
    input.value = input.value.replace(/\D/g, '').slice(0, 16);
}

// Format phone input
function formatPhone(input) {
    let value = input.value.replace(/[^\d+]/g, '');
    if (value.startsWith('62')) {
        value = '+' + value;
    } else if (value.startsWith('0')) {
        // Keep as is
    } else if (value && !value.startsWith('+')) {
        value = '0' + value;
    }
    input.value = value;
}

// Check if user is authenticated
async function checkAuth() {
    try {
        const response = await fetch('/api/user');
        const data = await response.json();
        return data.user || null;
    } catch (error) {
        return null;
    }
}

// Logout function
async function logout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (data.success) {
            window.location.href = '/';
        }
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Show error message
function showError(elementId, message) {
    const errorDiv = document.getElementById(elementId);
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }
}

// Hide error message
function hideError(elementId) {
    const errorDiv = document.getElementById(elementId);
    if (errorDiv) {
        errorDiv.style.display = 'none';
    }
}

// Show success message
function showSuccess(elementId, message) {
    const successDiv = document.getElementById(elementId);
    if (successDiv) {
        successDiv.textContent = message;
        successDiv.style.display = 'block';
    }
}

// Hide success message
function hideSuccess(elementId) {
    const successDiv = document.getElementById(elementId);
    if (successDiv) {
        successDiv.style.display = 'none';
    }
}

// Letter detail configuration used across pages
const LETTER_TYPE_NAMES = {
    death: 'Surat Laporan Kematian',
    birth: 'Surat Laporan Kelahiran',
    mutation: 'Surat Laporan Mutasi',
    other: 'Jenis Surat Lainnya'
};

const LETTER_DETAILS_CONFIG = {
    death: {
        sectionTitle: 'Data Laporan Kematian',
        sectionSubtitle: 'Lengkapi informasi warga yang meninggal dan unggah bukti pendukung.',
        attachmentRequired: true,
        attachmentHint: 'Unggah surat keterangan kematian atau bukti pendukung lainnya (PDF/JPG/PNG).',
        fields: [
            { id: 'deceasedName', label: 'Nama Lengkap Warga yang Meninggal', type: 'text', required: true },
            { 
                id: 'deceasedNik', 
                label: 'Nomor Induk Kependudukan (NIK) Warga yang Meninggal', 
                type: 'text', 
                required: true,
                attrs: { maxlength: 16, pattern: '\\d{16}', inputmode: 'numeric' },
                placeholder: '16 digit angka'
            },
            { id: 'deathDate', label: 'Tanggal Kematian', type: 'date', required: true },
            { id: 'deathLocation', label: 'Lokasi Kematian', type: 'text', required: true },
            { id: 'deathNotes', label: 'Keterangan Tambahan (Opsional)', type: 'textarea', required: false, fullWidth: true }
        ],
        summary(details) {
            if (!details) return '';
            const parts = [];
            if (details.deceasedName) parts.push(details.deceasedName);
            if (details.deathDate) parts.push(`Wafat: ${details.deathDate}`);
            if (details.deathLocation) parts.push(details.deathLocation);
            return parts.join(' • ');
        }
    },
    birth: {
        sectionTitle: 'Data Laporan Kelahiran',
        sectionSubtitle: 'Masukkan data bayi dan orang tua/wali.',
        attachmentRequired: false,
        attachmentHint: 'Unggah dokumen pendukung (opsional).',
        fields: [
            { id: 'babyName', label: 'Nama Lengkap Bayi', type: 'text', required: true },
            { id: 'parentName', label: 'Nama Lengkap Orang Tua/Wali', type: 'text', required: true },
            { 
                id: 'parentNik', 
                label: 'NIK Orang Tua/Wali', 
                type: 'text', 
                required: true,
                attrs: { maxlength: 16, pattern: '\\d{16}', inputmode: 'numeric' },
                placeholder: '16 digit angka'
            },
            { id: 'babyBirthDate', label: 'Tanggal Lahir Bayi', type: 'date', required: true },
            { 
                id: 'babyGender', 
                label: 'Jenis Kelamin Bayi', 
                type: 'select', 
                required: true,
                options: [
                    { value: '', label: 'Pilih Jenis Kelamin' },
                    { value: 'laki-laki', label: 'Laki-Laki' },
                    { value: 'perempuan', label: 'Perempuan' }
                ]
            }
        ],
        summary(details) {
            if (!details) return '';
            const parts = [];
            if (details.babyName) parts.push(details.babyName);
            if (details.babyBirthDate) parts.push(`Lahir: ${details.babyBirthDate}`);
            return parts.join(' • ');
        }
    },
    mutation: {
        sectionTitle: 'Data Laporan Mutasi',
        sectionSubtitle: 'Isi detail perpindahan alamat dan jenis mutasi.',
        attachmentRequired: false,
        attachmentHint: 'Unggah dokumen pendukung mutasi (opsional).',
        fields: [
            { id: 'mutationName', label: 'Nama Lengkap', type: 'text', required: true },
            { 
                id: 'mutationNik', 
                label: 'Nomor Induk Kependudukan (NIK)', 
                type: 'text', 
                required: true,
                attrs: { maxlength: 16, pattern: '\\d{16}', inputmode: 'numeric' },
                placeholder: '16 digit angka'
            },
            { id: 'moveDate', label: 'Tanggal Pindah', type: 'date', required: true },
            { id: 'oldAddress', label: 'Alamat Lama', type: 'textarea', required: true, fullWidth: true },
            { id: 'newAddress', label: 'Alamat Baru', type: 'textarea', required: true, fullWidth: true },
            { 
                id: 'mutationType', 
                label: 'Jenis Mutasi', 
                type: 'select', 
                required: true,
                options: [
                    { value: '', label: 'Pilih Jenis Mutasi' },
                    { value: 'masuk', label: 'Mutasi Masuk' },
                    { value: 'keluar', label: 'Mutasi Keluar' }
                ]
            }
        ],
        summary(details) {
            if (!details) return '';
            const parts = [];
            if (details.mutationName) parts.push(details.mutationName);
            if (details.mutationType) parts.push(`Mutasi ${details.mutationType}`);
            if (details.moveDate) parts.push(`Tanggal: ${details.moveDate}`);
            return parts.join(' • ');
        }
    },
    other: {
        sectionTitle: '',
        sectionSubtitle: '',
        attachmentRequired: false,
        attachmentHint: 'Unggah dokumen pendukung (opsional).',
        fields: [],
        summary() {
            return '';
        }
    }
};

function getLetterTypeName(type) {
    return LETTER_TYPE_NAMES[type] || type;
}

function getLetterDetailEntries(type, details) {
    const config = LETTER_DETAILS_CONFIG[type];
    if (!config || !details) return [];
    return config.fields.map(field => ({
        label: field.label,
        value: details[field.id] || '-'
    }));
}

function formatLetterDetailSummary(type, details) {
    const config = LETTER_DETAILS_CONFIG[type];
    if (!config || !config.summary) return '';
    return config.summary(details || {});
}

window.LETTER_DETAILS_CONFIG = LETTER_DETAILS_CONFIG;
window.getLetterTypeName = getLetterTypeName;
window.getLetterDetailEntries = getLetterDetailEntries;
window.formatLetterDetailSummary = formatLetterDetailSummary;

// Mobile Menu Toggle (Burger Menu)
function initMobileMenu() {
    const burgerMenu = document.getElementById('burgerMenu');
    const navMenu = document.getElementById('navMenu');

    if (burgerMenu && navMenu) {
        burgerMenu.addEventListener('click', () => {
            burgerMenu.classList.toggle('active');
            navMenu.classList.toggle('active');
        });

        // Close menu when clicking on a link
        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                burgerMenu.classList.remove('active');
                navMenu.classList.remove('active');
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!burgerMenu.contains(e.target) && !navMenu.contains(e.target)) {
                burgerMenu.classList.remove('active');
                navMenu.classList.remove('active');
            }
        });
    }
}

// Initialize mobile menu when DOM is ready
function initIcons() {
    if (window.feather && typeof window.feather.replace === 'function') {
        window.feather.replace();
    }
}

function initGlobalUI() {
    initMobileMenu();
    initIcons();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initGlobalUI);
} else {
    initGlobalUI();
}

