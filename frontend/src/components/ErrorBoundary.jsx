import React from "react";

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: "100vh",
          backgroundColor: "#09090b",
          color: "#fafafa",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "24px",
          fontFamily: "system-ui, sans-serif",
          boxSizing: "border-box"
        }}>
          <div style={{
            maxWidth: "600px",
            width: "100%",
            backgroundColor: "#18181b",
            border: "1px solid #27272a",
            borderRadius: "16px",
            padding: "24px",
            boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)"
          }}>
            <h2 style={{ fontSize: "18px", fontWeight: "bold", color: "#f87171", margin: "0 0 12px 0" }}>
              Application Render Error
            </h2>
            <p style={{ fontSize: "14px", color: "#a1a1aa", margin: "0 0 16px 0", wordBreak: "break-word" }}>
              {this.state.error?.message || "An unexpected error occurred."}
            </p>
            {this.state.error?.stack && (
              <pre style={{
                fontSize: "12px",
                textAlign: "left",
                backgroundColor: "rgba(0, 0, 0, 0.6)",
                padding: "12px",
                borderRadius: "8px",
                overflow: "auto",
                maxHeight: "200px",
                color: "#71717a",
                margin: "0 0 16px 0",
                whiteSpace: "pre-wrap"
              }}>
                {this.state.error.stack}
              </pre>
            )}
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
              style={{
                padding: "8px 16px",
                backgroundColor: "#3b82f6",
                color: "#ffffff",
                border: "none",
                borderRadius: "10px",
                fontSize: "14px",
                fontWeight: "500",
                cursor: "pointer"
              }}
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
