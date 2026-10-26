CREATE TABLE IF NOT EXISTS businesses (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    business_type TEXT NOT NULL DEFAULT 'general',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    business_id BIGINT REFERENCES businesses(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    phone TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN
      ('superadmin','platform_admin','admin','billing_user','customer')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (business_id, username)
);
CREATE UNIQUE INDEX IF NOT EXISTS users_platform_username_uq
  ON users(username) WHERE business_id IS NULL;
CREATE INDEX IF NOT EXISTS users_phone_idx ON users(business_id, phone);

CREATE TABLE IF NOT EXISTS products (
    id BIGSERIAL PRIMARY KEY,
    business_id BIGINT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sku TEXT,
    price NUMERIC(12,2) NOT NULL CHECK(price >= 0),
    stock NUMERIC(12,3) NOT NULL DEFAULT 0 CHECK(stock >= 0),
    gst_rate NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK(gst_rate >= 0 AND gst_rate <= 100),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (business_id, sku)
);

CREATE TABLE IF NOT EXISTS sales (
    id BIGSERIAL PRIMARY KEY,
    business_id BIGINT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    customer_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    idempotency_key TEXT NOT NULL,
    subtotal NUMERIC(12,2) NOT NULL,
    gst_total NUMERIC(12,2) NOT NULL,
    total NUMERIC(12,2) NOT NULL,
    points_awarded INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (business_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS sale_items (
    id BIGSERIAL PRIMARY KEY,
    sale_id BIGINT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id BIGINT NOT NULL REFERENCES products(id),
    product_name TEXT NOT NULL,
    quantity NUMERIC(12,3) NOT NULL CHECK(quantity > 0),
    unit_price NUMERIC(12,2) NOT NULL,
    gst_rate NUMERIC(5,2) NOT NULL,
    line_subtotal NUMERIC(12,2) NOT NULL,
    line_gst NUMERIC(12,2) NOT NULL,
    line_total NUMERIC(12,2) NOT NULL
);
CREATE TABLE IF NOT EXISTS customer_loyalty (
    business_id BIGINT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    customer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points INTEGER NOT NULL DEFAULT 0 CHECK(points >= 0),
    PRIMARY KEY (business_id, customer_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    business_id BIGINT REFERENCES businesses(id) ON DELETE SET NULL,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
