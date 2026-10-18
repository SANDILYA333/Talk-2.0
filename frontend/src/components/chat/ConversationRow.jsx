import { Avatar } from "@heroui/react";
import { AvatarWithOnlineIndicator } from "./AvatarWithOnlineIndicator";
import { formatConversationTime, formatUnreadBadge, formatSnippet } from "../../lib/conversationView";
import { useAuthStore } from "../../store/useAuthStore";

export function ConversationRow({ user, selected, onSelect }) {
  const currentUserId = useAuthStore((state) => state.authUser?._id);

  const isOwn = Boolean(
    user.lastMessage?.senderId && String(user.lastMessage.senderId) === String(currentUserId)
  );

  const displaySnippet = formatSnippet({
    text: user.snippet,
    isOwn,
    state: user.lastMessage?.state || "ok",
  });

  const timeLabel = formatConversationTime(user.lastMessage?.createdAt || user.lastMessageAt);
  const badgeText = formatUnreadBadge(user.unreadCount);
  const hasUnread = Boolean(badgeText);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full items-center gap-3 border-b border-border px-3 py-2.5 text-left cursor-pointer transition-colors motion-reduce:transition-none ${
        selected ? "bg-accent-soft" : "hover:bg-muted/10"
      }`}
    >
      <AvatarWithOnlineIndicator isOnline={user.isOnline ?? true}>
        <Avatar className="size-12 shrink-0">
          <Avatar.Image alt={user.name} src={user.avatarUrl} />
          <Avatar.Fallback className="text-sm font-medium">{user.initials}</Avatar.Fallback>
        </Avatar>
      </AvatarWithOnlineIndicator>

      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-1">
          <p
            className={`truncate text-[15px] ${
              hasUnread ? "font-bold text-foreground" : "font-semibold text-foreground"
            }`}
          >
            {user.name}
          </p>
          {timeLabel ? (
            <span
              className={`text-[11px] tabular-nums shrink-0 ml-1.5 ${
                hasUnread ? "font-semibold text-primary" : "text-muted"
              }`}
            >
              {timeLabel}
            </span>
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-2 mt-0.5">
          {displaySnippet ? (
            <p
              className={`truncate text-xs ${
                hasUnread ? "font-semibold text-foreground" : "text-muted"
              }`}
            >
              {displaySnippet}
            </p>
          ) : (
            <span />
          )}

          {hasUnread ? (
            <span
              aria-label={`${user.unreadCount} unread message${user.unreadCount === 1 ? "" : "s"}`}
              className="inline-flex items-center justify-center min-w-[1.25rem] h-4.5 px-1.5 rounded-full bg-primary text-primary-foreground text-[11px] font-bold shrink-0 shadow-xs"
            >
              {badgeText}
            </span>
          ) : null}
        </div>
      </div>
    </button>
  );
}
