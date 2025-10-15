import logging
import asyncio
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

# --- DATABASE SETUP ---
DATABASE_URL = "sqlite:///database.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redefine the database models to match app.py EXACTLY
class ManagedGroup(Base):
    __tablename__ = 'managed_group'
    id = Column(Integer, primary_key=True)
    telegram_chat_id = Column(String(100), unique=True, nullable=False)
    bot_token = Column(String(100), nullable=False)
    spam_keywords = relationship('SpamKeyword', backref='group', lazy=True)
    allowed_usernames = relationship('AllowedUsername', backref='group', lazy=True)
    allowed_domains = relationship('AllowedDomain', backref='group', lazy=True) # NEW
    authorized_users = relationship('AuthorizedUser', backref='group', lazy=True) # NEW

class SpamKeyword(Base):
    __tablename__ = 'spam_keyword'
    id = Column(Integer, primary_key=True)
    keyword = Column(String(100), nullable=False)
    group_id = Column(Integer, ForeignKey('managed_group.id'), nullable=False)

class AllowedUsername(Base):
    __tablename__ = 'allowed_username'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False)
    group_id = Column(Integer, ForeignKey('managed_group.id'), nullable=False)

class AllowedDomain(Base): # NEW
    __tablename__ = 'allowed_domain'
    id = Column(Integer, primary_key=True)
    domain = Column(String(100), nullable=False)
    group_id = Column(Integer, ForeignKey('managed_group.id'), nullable=False)

class AuthorizedUser(Base): # NEW
    __tablename__ = 'authorized_user'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(100), nullable=False)
    group_id = Column(Integer, ForeignKey('managed_group.id'), nullable=False)


# --- LOGGING SETUP ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

running_bots = {}

def get_rules_from_db(chat_id):
    """Fetches all moderation rules for a specific chat_id from the database."""
    db = SessionLocal()
    try:
        group = db.query(ManagedGroup).filter(ManagedGroup.telegram_chat_id == str(chat_id)).first()
        if not group:
            return None

        # Compile all rules into a dictionary
        rules = {
            'spam_keywords': [kw.keyword.lower() for kw in group.spam_keywords],
            'allowed_usernames': [user.username.lower() for user in group.allowed_usernames],
            'allowed_domains': [d.domain.lower() for d in group.allowed_domains],
            'authorized_users': [int(user.user_id) for user in group.authorized_users],
        }
        return rules
    finally:
        db.close()

async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Checks every message against the rules fetched from the database."""
    if not update.message: return

    chat_id = update.effective_chat.id
    user = update.message.from_user
    
    rules = get_rules_from_db(chat_id)

    if not rules: return # This group isn't managed by us.

    # --- RULE 1: CHECK FOR AUTHORIZED USERS (MOST IMPORTANT) ---
    # If the message sender is in the authorized list, ignore all other rules.
    if user and user.id in rules['authorized_users']:
        return

    text_to_check = (update.message.text or update.message.caption or "").lower()
    delete_reason = None
    
    # --- RULE 2: CHECK FOR FORWARDED MESSAGES ---
    if update.message.forward_from or update.message.forward_from_chat:
        delete_reason = "was a forwarded message."

    # --- RULE 3: CHECK FOR SPAM KEYWORDS ---
    if not delete_reason and any(keyword in text_to_check for keyword in rules['spam_keywords']):
        delete_reason = "contained a forbidden keyword."
    
    # --- RULE 4: CHECK FOR LINKS and @MENTIONS ---
    if not delete_reason and update.message.entities:
        for entity in update.message.entities:
            # Check for any kind of link (handles t.me, http, etc.)
            if entity.type in ['url', 'text_link']:
                url = entity.url if entity.type == 'text_link' else text_to_check[entity.offset:entity.offset+entity.length]
                # Check if the URL contains any of the allowed domains
                if not any(domain in url for domain in rules['allowed_domains']):
                    delete_reason = "contained an unauthorized link."
                    break # One bad link is enough
            
            # Check for @mentions
            if entity.type == 'mention':
                mention = text_to_check[entity.offset+1:entity.offset+entity.length]
                if mention not in rules['allowed_usernames']:
                    delete_reason = "contained an unauthorized username mention."
                    break
    
    # If a reason was found, delete the message
    if delete_reason:
        try:
            await update.message.delete()
            logger.info(f"Deleted message in chat {chat_id} from {user.first_name} because it {delete_reason}")
        except Exception as e:
            logger.error(f"Failed to delete message in chat {chat_id}: {e}")

async def start_bot_instance(token):
    if token in running_bots: return
    try:
        application = Application.builder().token(token).build()
        application.add_handler(MessageHandler(filters.ALL & (~filters.COMMAND), check_message))
        await application.initialize()
        await application.start()
        await application.updater.start_polling()
        running_bots[token] = application
        logger.info(f"Successfully started bot instance for token {token[:10]}...")
    except Exception as e:
        logger.error(f"Failed to start bot with token {token[:10]}... Error: {e}")

async def main():
    while True:
        db = SessionLocal()
        try:
            all_tokens = [token for token, in db.query(ManagedGroup.bot_token).distinct()]
            for token in all_tokens:
                if token not in running_bots:
                    asyncio.create_task(start_bot_instance(token))
        finally:
            db.close()
        await asyncio.sleep(30)

if __name__ == '__main__':
    logger.info("Bot worker started. It will now poll the database for bots to run.")
    asyncio.run(main())