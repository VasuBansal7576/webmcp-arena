CREATE TABLE `audits` (
	`id` text PRIMARY KEY NOT NULL,
	`idempotency_key` text UNIQUE,
	`version` text NOT NULL CHECK (`version` IN ('vulnerable', 'fixed')),
	`state` text NOT NULL CHECK (`state` IN ('awaiting_approval', 'running', 'waiting_for_effects', 'completed', 'failed')),
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`lease_id` text,
	`lease_expires_at` integer,
	`payload` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_audits_state_updated_at` ON `audits` (`state`,`updated_at`);--> statement-breakpoint
CREATE INDEX `idx_audits_expires_at` ON `audits` (`expires_at`);
