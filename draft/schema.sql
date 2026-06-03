-- =====================================================
-- FAMILY WEBSITE DATABASE SCHEMA
-- Version: 2.0
-- Description: Complete schema for 1000+ member family tree
-- =====================================================

-- =====================================================
-- CORE TABLES
-- =====================================================

-- Family members table (core of the system)
CREATE TABLE persons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Basic Information
    name TEXT NOT NULL,
    gender TEXT CHECK(gender IN ('M', 'F', 'Other')),
    
    -- Birth Information
    birth_date TEXT NULL,
    birth_place TEXT NULL,
    
    -- Death Information
    death_date TEXT NULL,
    death_place TEXT NULL,
    is_living BOOLEAN DEFAULT 1,
    
    -- Family Relationships
    father_id INTEGER NULL,
    mother_id INTEGER NULL,
    
    -- Professional & Personal
    job TEXT NULL,
    lineage TEXT NULL,  -- Family lineage description
    
    -- Privacy & Status
    is_public BOOLEAN DEFAULT 1,  -- Can this person be viewed by public?
    privacy_level TEXT DEFAULT 'public' CHECK(privacy_level IN ('public', 'members_only', 'private')),
    
    -- Media & Notes
    photo_url TEXT NULL,
    notes TEXT NULL,
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NULL,  -- Admin username who created
    updated_by TEXT NULL,  -- Admin username who last updated
    
    -- Foreign Keys
    FOREIGN KEY (father_id) REFERENCES persons(id) ON DELETE SET NULL,
    FOREIGN KEY (mother_id) REFERENCES persons(id) ON DELETE SET NULL,
    
    -- Constraints
    CHECK (
        (death_date IS NULL OR birth_date IS NULL OR death_date >= birth_date)
    )
);

-- Indexes for persons table
CREATE INDEX idx_persons_name ON persons(name);
CREATE INDEX idx_persons_father ON persons(father_id);
CREATE INDEX idx_persons_mother ON persons(mother_id);
CREATE INDEX idx_persons_birth ON persons(birth_date);
CREATE INDEX idx_persons_living ON persons(is_living);
CREATE INDEX idx_persons_privacy ON persons(privacy_level);

-- =====================================================
-- RELATIONSHIP TABLES
-- =====================================================

-- Spouse relationships (clean, single table design)
CREATE TABLE spouse_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person1_id INTEGER NOT NULL,
    person2_id INTEGER NOT NULL,
    
    -- Marriage Details
    marriage_date TEXT NULL,
    marriage_place TEXT NULL,
    is_divorced BOOLEAN DEFAULT 0,
    divorce_date TEXT NULL,
    notes TEXT NULL,
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints & Foreign Keys
    UNIQUE(person1_id, person2_id),
    FOREIGN KEY(person1_id) REFERENCES persons(id) ON DELETE CASCADE,
    FOREIGN KEY(person2_id) REFERENCES persons(id) ON DELETE CASCADE,
    CHECK(person1_id < person2_id)  -- Prevents duplicate pairs
);

-- Indexes for spouse relationships
CREATE INDEX idx_spouse_person1 ON spouse_relationships(person1_id);
CREATE INDEX idx_spouse_person2 ON spouse_relationships(person2_id);
CREATE INDEX idx_spouse_marriage ON spouse_relationships(marriage_date);

-- Children relationships (for tracking multiple marriages)
CREATE TABLE child_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_id INTEGER NOT NULL,
    father_id INTEGER NULL,
    mother_id INTEGER NULL,
    relationship_type TEXT DEFAULT 'biological' CHECK(relationship_type IN ('biological', 'adopted', 'step', 'foster')),
    notes TEXT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(child_id) REFERENCES persons(id) ON DELETE CASCADE,
    FOREIGN KEY(father_id) REFERENCES persons(id) ON DELETE SET NULL,
    FOREIGN KEY(mother_id) REFERENCES persons(id) ON DELETE SET NULL,
    
    -- Ensure at least one parent is specified
    CHECK (father_id IS NOT NULL OR mother_id IS NOT NULL)
);

CREATE INDEX idx_child_relationships_child ON child_relationships(child_id);
CREATE INDEX idx_child_relationships_father ON child_relationships(father_id);
CREATE INDEX idx_child_relationships_mother ON child_relationships(mother_id);

-- =====================================================
-- CONTENT MANAGEMENT TABLES
-- =====================================================

-- Biographies table (separate from persons for rich content)
CREATE TABLE biographies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER UNIQUE NOT NULL,
    
    -- Content
    headline TEXT NULL,  -- Brief intro for card view (max 200 chars)
    short_bio TEXT NULL, -- Medium length for listings
    full_bio TEXT,       -- Complete biography
    
    -- Achievements stored as JSON for flexibility
    achievements TEXT NULL,  -- JSON array: [{"title": "Award", "year": "2020", "description": "..."}]
    
    -- Display Settings
    is_featured BOOLEAN DEFAULT 0,
    featured_until TEXT NULL,  -- For rotating featured bios
    ord INTEGER DEFAULT 1,     -- Sort order
    
    -- Media
    portrait_url TEXT NULL,    -- Custom portrait for biography
    gallery_json TEXT NULL,    -- JSON array of additional photos
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NULL,
    
    FOREIGN KEY(person_id) REFERENCES persons(id) ON DELETE CASCADE
);

-- Indexes for biographies
CREATE INDEX idx_biographies_featured ON biographies(is_featured, ord);
CREATE INDEX idx_biographies_person ON biographies(person_id);

-- Timeline events for History page
CREATE TABLE timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Dating
    year INTEGER NOT NULL,
    year_end INTEGER NULL,  -- For date ranges (e.g., 1914-1918)
    is_approximate BOOLEAN DEFAULT 0,
    
    -- Content
    title TEXT NOT NULL,
    description TEXT,
    event_type TEXT CHECK(event_type IN ('family', 'historical', 'migration', 'achievement', 'cultural')) DEFAULT 'family',
    
    -- Media
    image_url TEXT NULL,
    video_url TEXT NULL,
    document_url TEXT NULL,
    
    -- Display
    ord INTEGER DEFAULT 1,
    is_highlighted BOOLEAN DEFAULT 0,  -- Featured events
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NULL,
    
    -- Constraints
    CHECK (year_end IS NULL OR year_end >= year)
);

-- Indexes for timeline
CREATE INDEX idx_timeline_year ON timeline_events(year, ord);
CREATE INDEX idx_timeline_type ON timeline_events(event_type);
CREATE INDEX idx_timeline_highlighted ON timeline_events(is_highlighted);

-- Link persons to timeline events (many-to-many)
CREATE TABLE person_timeline (
    person_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    
    -- Context
    role TEXT NULL,           -- e.g., "participant", "witness", "subject", "narrator"
    notes TEXT NULL,
    ord INTEGER DEFAULT 1,
    
    PRIMARY KEY (person_id, event_id),
    FOREIGN KEY(person_id) REFERENCES persons(id) ON DELETE CASCADE,
    FOREIGN KEY(event_id) REFERENCES timeline_events(id) ON DELETE CASCADE
);

CREATE INDEX idx_person_timeline_event ON person_timeline(event_id);

-- =====================================================
-- HONOR/ACHIEVEMENTS TABLE (Legacy support)
-- =====================================================

CREATE TABLE honor_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,           -- Person's name
    field TEXT NULL,              -- Field of achievement
    achievement TEXT NULL,        -- Achievement description
    photo_url TEXT NULL,
    bio TEXT NULL,                -- Short biography
    ord INTEGER DEFAULT 1,
    
    -- Link to person if exists in database
    person_id INTEGER NULL,
    
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(person_id) REFERENCES persons(id) ON DELETE SET NULL
);

CREATE INDEX idx_honor_ord ON honor_items(ord);
CREATE INDEX idx_honor_person ON honor_items(person_id);

-- =====================================================
-- SITE MANAGEMENT TABLES
-- =====================================================

-- Site pages content management
CREATE TABLE site_pages (
    slug TEXT PRIMARY KEY,        -- URL identifier (e.g., 'home', 'history', 'support')
    title TEXT NOT NULL,
    subtitle TEXT NULL,
    content TEXT,                 -- Main page content (HTML/Markdown)
    
    -- Page specific fields (flexible JSON storage)
    page_data TEXT NULL,          -- JSON object for page-specific settings
    
    -- PDF Management (for Tree page)
    pdf_url TEXT NULL,
    pdf_title TEXT NULL,
    pdf_description TEXT NULL,
    pdf_last_updated TEXT NULL,
    
    -- Support Page Fields
    fund_name TEXT NULL,
    bank_name TEXT NULL,
    account_number TEXT NULL,
    whatsapp TEXT NULL,
    email TEXT NULL,
    
    -- System Fields
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT NULL,
    is_published BOOLEAN DEFAULT 1,
    view_count INTEGER DEFAULT 0
);

-- Site settings (key-value pairs for global configuration)
CREATE TABLE site_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    setting_type TEXT DEFAULT 'text' CHECK(setting_type IN ('text', 'number', 'boolean', 'json', 'image')),
    description TEXT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT NULL
);

-- Insert default settings
INSERT INTO site_settings (setting_key, setting_value, setting_type, description) VALUES
    ('site_title', 'Our Family Tree', 'text', 'Website title'),
    ('site_description', 'Tracing our family history across generations', 'text', 'Meta description'),
    ('members_count', '0', 'number', 'Total members count (auto-updated)'),
    ('generations_count', '0', 'number', 'Number of generations'),
    ('theme_color', '#4A5568', 'text', 'Primary theme color'),
    ('allow_public_access', 'true', 'boolean', 'Allow non-logged-in users'),
    ('maintenance_mode', 'false', 'boolean', 'Put site in maintenance mode'),
    ('contact_email', 'admin@familytree.com', 'text', 'Admin contact email');

-- =====================================================
-- USER MANAGEMENT TABLES
-- =====================================================

-- Admin users
CREATE TABLE admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NULL,
    
    -- Permissions (JSON array of permissions)
    permissions TEXT DEFAULT '[]',  -- e.g., ["manage_members", "manage_content", "view_messages"]
    
    -- Status
    is_active BOOLEAN DEFAULT 1,
    last_login TEXT NULL,
    last_ip TEXT NULL,
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NULL,
    
    -- Two-factor authentication (optional)
    two_factor_secret TEXT NULL,
    two_factor_enabled BOOLEAN DEFAULT 0
);

-- Family member user accounts
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER UNIQUE,      -- Link to family tree
    
    -- Account Information
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'member' CHECK(role IN ('member', 'editor', 'admin', 'viewer')),
    
    -- Status
    is_active BOOLEAN DEFAULT 1,
    email_verified BOOLEAN DEFAULT 0,
    verification_token TEXT NULL,
    reset_token TEXT NULL,
    reset_token_expires TEXT NULL,
    
    -- Activity
    last_login TEXT NULL,
    last_ip TEXT NULL,
    login_count INTEGER DEFAULT 0,
    
    -- Preferences
    preferences TEXT NULL,          -- JSON object for user preferences
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(person_id) REFERENCES persons(id) ON DELETE SET NULL
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_person ON users(person_id);
CREATE INDEX idx_users_role ON users(role);

-- Notifications for users
CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    
    -- Content
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    notification_type TEXT CHECK(notification_type IN ('info', 'success', 'warning', 'alert')) DEFAULT 'info',
    
    -- Link to related content (optional)
    link_url TEXT NULL,
    link_text TEXT NULL,
    
    -- Status
    is_read BOOLEAN DEFAULT 0,
    read_at TEXT NULL,
    is_archived BOOLEAN DEFAULT 0,
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NULL,
    
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_notifications_user ON notifications(user_id, is_read, created_at);

-- =====================================================
-- SUPPORT & COMMUNICATION TABLES
-- =====================================================

-- Support messages from website visitors
CREATE TABLE support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Sender Information
    sender_name TEXT NOT NULL,
    email TEXT NULL,
    phone TEXT NULL,
    
    -- Message Content
    message_type TEXT CHECK(message_type IN ('suggestion', 'complaint', 'question', 'support_offer', 'general', 'bug_report')) DEFAULT 'general',
    subject TEXT NULL,
    message TEXT NOT NULL,
    
    -- Attachments (JSON array of file paths)
    attachments TEXT NULL,
    
    -- Status Tracking
    is_read BOOLEAN DEFAULT 0,
    read_at TEXT NULL,
    read_by TEXT NULL,
    
    is_archived BOOLEAN DEFAULT 0,
    archived_at TEXT NULL,
    
    -- Response
    response TEXT NULL,
    responded_at TEXT NULL,
    responded_by TEXT NULL,
    
    -- Priority
    priority INTEGER DEFAULT 1,  -- 1=Low, 2=Medium, 3=High
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NULL,
    user_agent TEXT NULL
);

CREATE INDEX idx_support_unread ON support_messages(is_read, created_at);
CREATE INDEX idx_support_type ON support_messages(message_type);
CREATE INDEX idx_support_priority ON support_messages(priority);

-- Financial support tracking
CREATE TABLE financial_support (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Donor Information
    donor_name TEXT NOT NULL,
    donor_email TEXT NULL,
    donor_phone TEXT NULL,
    
    -- Financial Details
    amount DECIMAL(10,2) NOT NULL,
    currency TEXT DEFAULT 'USD',
    payment_method TEXT CHECK(payment_method IN ('bank_transfer', 'cash', 'check', 'online', 'other')) DEFAULT 'bank_transfer',
    
    -- Status
    status TEXT CHECK(status IN ('pending', 'completed', 'failed', 'refunded')) DEFAULT 'pending',
    transaction_id TEXT NULL,
    transaction_date TEXT NULL,
    
    -- Additional Information
    notes TEXT NULL,
    is_anonymous BOOLEAN DEFAULT 0,
    is_public BOOLEAN DEFAULT 1,  -- Show on donor wall?
    
    -- For recurring support
    is_recurring BOOLEAN DEFAULT 0,
    recurring_frequency TEXT NULL,
    
    -- System Fields
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    recorded_by TEXT NULL,  -- Admin who recorded this
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    -- Link to user if they have account
    user_id INTEGER NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_financial_status ON financial_support(status);
CREATE INDEX idx_financial_date ON financial_support(transaction_date);
CREATE INDEX idx_financial_donor ON financial_support(donor_name);

-- Donor wall (for public display)
CREATE TABLE donor_wall (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    support_id INTEGER UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    message TEXT NULL,
    amount_display TEXT NULL,  -- Formatted for display (e.g., "***" for anonymous)
    show_amount BOOLEAN DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(support_id) REFERENCES financial_support(id) ON DELETE CASCADE
);

-- =====================================================
-- MEDIA MANAGEMENT TABLES
-- =====================================================

-- Media gallery for family photos and documents
CREATE TABLE media_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Basic Information
    title TEXT NOT NULL,
    description TEXT NULL,
    media_type TEXT CHECK(media_type IN ('photo', 'document', 'video', 'audio')) DEFAULT 'photo',
    
    -- File Information
    file_url TEXT NOT NULL,
    thumbnail_url TEXT NULL,
    file_size INTEGER NULL,  -- in bytes
    mime_type TEXT NULL,
    
    -- Metadata
   拍摄日期 TEXT NULL,  -- Date taken/created (using Chinese chars as example, but keep ASCII: 'capture_date')
    capture_date TEXT NULL,
    location TEXT NULL,
    
    -- Tags & Categories
    tags TEXT NULL,  -- JSON array of tags
    category TEXT NULL,
    
    -- Privacy
    is_public BOOLEAN DEFAULT 1,
    
    -- System Fields
    uploaded_by TEXT NULL,
    uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
    view_count INTEGER DEFAULT 0
);

CREATE INDEX idx_media_type ON media_items(media_type);
CREATE INDEX idx_media_date ON media_items(capture_date);
CREATE INDEX idx_media_public ON media_items(is_public);

-- Link media to persons (many-to-many)
CREATE TABLE person_media (
    person_id INTEGER NOT NULL,
    media_id INTEGER NOT NULL,
    
    -- Context
    relationship TEXT NULL,  -- e.g., "portrait", "family photo", "document"
    is_primary BOOLEAN DEFAULT 0,  -- Primary photo for this person
    notes TEXT NULL,
    ord INTEGER DEFAULT 1,
    
    PRIMARY KEY (person_id, media_id),
    FOREIGN KEY(person_id) REFERENCES persons(id) ON DELETE CASCADE,
    FOREIGN KEY(media_id) REFERENCES media_items(id) ON DELETE CASCADE
);

CREATE INDEX idx_person_media_media ON person_media(media_id);
CREATE INDEX idx_person_media_primary ON person_media(person_id, is_primary);

-- Link media to timeline events
CREATE TABLE timeline_media (
    event_id INTEGER NOT NULL,
    media_id INTEGER NOT NULL,
    is_primary BOOLEAN DEFAULT 0,
    notes TEXT NULL,
    ord INTEGER DEFAULT 1,
    
    PRIMARY KEY (event_id, media_id),
    FOREIGN KEY(event_id) REFERENCES timeline_events(id) ON DELETE CASCADE,
    FOREIGN KEY(media_id) REFERENCES media_items(id) ON DELETE CASCADE
);

-- =====================================================
-- SYSTEM LOGS & AUDIT TABLES
-- =====================================================

-- Track all changes for accountability
CREATE TABLE system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Who
    admin_username TEXT NULL,
    user_id INTEGER NULL,
    
    -- What
    action TEXT NOT NULL,  -- 'CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'EXPORT'
    table_name TEXT,
    record_id INTEGER,
    
    -- Changes (JSON)
    old_value TEXT,  -- JSON of old values
    new_value TEXT,  -- JSON of new values
    
    -- Context
    ip_address TEXT,
    user_agent TEXT,
    session_id TEXT NULL,
    
    -- When
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_logs_admin ON system_logs(admin_username, created_at);
CREATE INDEX idx_logs_user ON system_logs(user_id, created_at);
CREATE INDEX idx_logs_table ON system_logs(table_name, record_id);
CREATE INDEX idx_logs_action ON system_logs(action, created_at);

-- Export history (for GDPR compliance)
CREATE TABLE export_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exported_by TEXT NOT NULL,  -- Admin username
    export_type TEXT CHECK(export_type IN ('full_backup', 'gedcom', 'pdf_tree', 'member_list', 'audit_log')),
    file_name TEXT NOT NULL,
    file_size INTEGER,
    record_count INTEGER,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- TRIGGERS FOR AUTOMATED UPDATES
-- =====================================================

-- Update timestamp triggers
CREATE TRIGGER update_persons_timestamp 
AFTER UPDATE ON persons
BEGIN
    UPDATE persons SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_spouse_timestamp 
AFTER UPDATE ON spouse_relationships
BEGIN
    UPDATE spouse_relationships SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_biographies_timestamp 
AFTER UPDATE ON biographies
BEGIN
    UPDATE biographies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_timeline_timestamp 
AFTER UPDATE ON timeline_events
BEGIN
    UPDATE timeline_events SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER update_users_timestamp 
AFTER UPDATE ON users
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Update member count in site_settings when persons table changes
CREATE TRIGGER update_member_count_insert
AFTER INSERT ON persons
BEGIN
    UPDATE site_settings 
    SET setting_value = (SELECT COUNT(*) FROM persons),
        updated_at = CURRENT_TIMESTAMP
    WHERE setting_key = 'members_count';
END;

CREATE TRIGGER update_member_count_delete
AFTER DELETE ON persons
BEGIN
    UPDATE site_settings 
    SET setting_value = (SELECT COUNT(*) FROM persons),
        updated_at = CURRENT_TIMESTAMP
    WHERE setting_key = 'members_count';
END;

-- =====================================================
-- VIEWS FOR COMMON QUERIES
-- =====================================================

-- View for complete family tree structure
CREATE VIEW v_family_tree AS
SELECT 
    p.id,
    p.name,
    p.gender,
    p.birth_date,
    p.death_date,
    p.is_living,
    p.photo_url,
    father.name AS father_name,
    mother.name AS mother_name,
    (
        SELECT COUNT(*) FROM child_relationships WHERE child_id = p.id
    ) AS children_count,
    (
        SELECT COUNT(*) FROM spouse_relationships 
        WHERE person1_id = p.id OR person2_id = p.id
    ) AS spouse_count
FROM persons p
LEFT JOIN persons father ON p.father_id = father.id
LEFT JOIN persons mother ON p.mother_id = mother.id;

-- View for public member listing
CREATE VIEW v_public_members AS
SELECT 
    id,
    name,
    gender,
    birth_date,
    death_date,
    is_living,
    photo_url,
    job,
    CASE 
        WHEN is_living = 1 THEN 'Living'
        ELSE 'Deceased'
    END AS status
FROM persons
WHERE is_public = 1 AND privacy_level = 'public'
ORDER BY name;

-- =====================================================
-- INITIAL DATA
-- =====================================================

-- Create default admin (password should be changed immediately)
-- Default password: admin123 (use proper hashing in application)
INSERT INTO admins (username, password_hash, email, full_name, permissions) VALUES 
    ('admin', '$2y$10$YourHashedPasswordHere', 'admin@familytree.com', 'System Administrator', '["*"]');

-- Initialize site pages
INSERT INTO site_pages (slug, title, subtitle, content, is_published) VALUES 
    ('home', 'Family Tree Home', 'Our Family Legacy', '<h1>Welcome to Our Family Tree</h1><p>Explore our family history across generations.</p>', 1),
    ('history', 'Family History', 'A Journey Through Time', '<h1>Our Family History</h1><p>The story of our family through the ages.</p>', 1),
    ('biographies', 'Member Biographies', 'Life Stories', '<h1>Family Member Biographies</h1><p>Read about the lives of our family members.</p>', 1),
    ('tree', 'Family Tree PDF', 'Complete Family Tree', '<h1>Family Tree PDF</h1><p>Download the complete family tree.</p>', 1),
    ('support', 'Support Our Family Website', 'Help Preserve Our Legacy', '<h1>Support Our Family Website</h1><p>Your contributions help maintain this site.</p>', 1);

-- Initialize timeline event types as site settings
INSERT INTO site_settings (setting_key, setting_value, setting_type, description) VALUES
    ('timeline_categories', '["family","historical","migration","achievement","cultural"]', 'json', 'Available timeline event categories'),
    ('privacy_levels', '["public","members_only","private"]', 'json', 'Privacy levels for persons'),
    ('support_message_types', '["suggestion","complaint","question","support_offer","general","bug_report"]', 'json', 'Types of support messages');

-- =====================================================
-- END OF SCHEMA
-- =====================================================