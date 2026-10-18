import { Play, Film, Loader2 } from "lucide-react";

function formatDuration(sec) {
  if (!sec || !Number.isFinite(sec)) return "";
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function MessageVideo({ src, poster, duration, onPlayRequested, isLoading }) {
  if (src) {
    return (
      <video
        src={src}
        poster={poster}
        controls
        playsInline
        autoPlay
        className="mb-1.5 max-h-52 max-w-full rounded-lg object-contain sm:max-h-64 sm:rounded-xl"
      />
    );
  }

  return (
    <button
      type="button"
      onClick={onPlayRequested}
      disabled={isLoading}
      aria-label="Play video attachment"
      className="relative mb-1.5 flex max-h-52 w-full min-w-[200px] max-w-full cursor-pointer items-center justify-center overflow-hidden rounded-lg bg-black/40 text-white sm:max-h-64 sm:rounded-xl group focus:outline-none focus:ring-2 focus:ring-accent"
    >
      {poster ? (
        <img
          src={poster}
          alt="Video poster preview"
          className="h-full w-full object-cover blur-[0.5px] group-hover:scale-105 transition-transform duration-200 motion-reduce:transform-none"
        />
      ) : (
        <div className="flex h-36 w-full items-center justify-center bg-surface/50 text-muted">
          <Film className="size-10" />
        </div>
      )}

      {/* Play Overlay */}
      <div className="absolute inset-0 flex items-center justify-center bg-black/25 group-hover:bg-black/35 transition-colors">
        <div className="flex size-12 items-center justify-center rounded-full bg-black/60 backdrop-blur-sm text-white shadow-md group-hover:scale-110 transition-transform motion-reduce:transform-none">
          {isLoading ? (
            <Loader2 className="size-6 animate-spin text-white" />
          ) : (
            <Play className="size-6 fill-white text-white ml-0.5" />
          )}
        </div>
      </div>

      {/* Duration Badge */}
      {duration ? (
        <div className="absolute bottom-2 right-2 rounded bg-black/70 px-1.5 py-0.5 text-[11px] font-mono text-white/90">
          {formatDuration(duration)}
        </div>
      ) : null}
    </button>
  );
}
