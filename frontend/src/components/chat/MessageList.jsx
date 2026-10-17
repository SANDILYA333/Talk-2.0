import { useEffect, useRef } from "react";
import useScrollToBottom from "../../hooks/useScrollToBottom";
import { MessageBubble } from "./MessageBubble";
import { NoConversationPlaceholder } from "./NoConversationPlaceholder";
import { useSelectedConversation } from "../../hooks/useSelectedConversation";
import { useChatStore } from "../../store/useChatStore";

export function MessageList() {
  const { activeConversation, activeConversationId } = useSelectedConversation();
  const topRef = useRef(null);
  const loadOlder = useChatStore((s) => s.loadOlder);
  const isLoadingOlder = useChatStore((s) => s.isLoadingOlder);

  const lastMessageId = activeConversation?.messages.at(-1)?.id;
  const containerRef = useScrollToBottom(activeConversationId, lastMessageId);

  useEffect(() => {
    const el = topRef.current;
    if (!el) return;
    const io = new IntersectionObserver(
      async ([e]) => {
        if (!e.isIntersecting) return;
        const c = containerRef.current;
        if (!c) return;
        const prev = c.scrollHeight;
        await loadOlder();
        requestAnimationFrame(() => {
          c.scrollTop += c.scrollHeight - prev;
        });
      },
      { root: containerRef.current }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [loadOlder, activeConversationId, containerRef]);

  return (
    <div className="relative flex flex-1 flex-col overflow-hidden">
      {activeConversation ? (
        <div
          ref={containerRef}
          className="flex flex-1 flex-col gap-1 overflow-y-auto overscroll-contain px-2 py-3 sm:px-3 sm:py-4"
        >
          <div ref={topRef} className="h-1" />
          {isLoadingOlder ? (
            <div className="py-1 text-center text-xs text-muted">
              Loading older messages…
            </div>
          ) : null}
          <p className="mb-3 text-center text-[11px] font-medium uppercase tracking-wide text-muted">
            Today
          </p>
          {activeConversation.messages.map((message) => (
            <MessageBubble key={message.id} message={message} />
          ))}
        </div>
      ) : (
        <NoConversationPlaceholder />
      )}
    </div>
  );
}

