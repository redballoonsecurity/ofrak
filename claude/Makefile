.PHONY: install uninstall clean

SKILL_NAME := ofrak-developer
SKILL_DIR := $(CURDIR)/$(SKILL_NAME)
CLAUDE_SKILLS_DIR := $(HOME)/.claude/skills
INSTALL_PATH := $(CLAUDE_SKILLS_DIR)/$(SKILL_NAME)

install:
	@echo "Installing $(SKILL_NAME) skill..."
	@mkdir -p $(CLAUDE_SKILLS_DIR)
	@ln -sf $(SKILL_DIR) $(INSTALL_PATH)
	@echo "✓ Skill installed at $(INSTALL_PATH)"

uninstall:
	@echo "Uninstalling $(SKILL_NAME) skill..."
	@rm -f $(INSTALL_PATH)
	@echo "✓ Skill uninstalled"

package:
	@echo "Packaging $(SKILL_NAME) skill..."
	@zip -r $(SKILL_NAME).zip $(SKILL_DIR)
	@echo "✓ Skill packaged at $(SKILL_NAME).zip"

clean: uninstall
