import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("App UI integration", () => {
  it("renders title, toggles TR/EN language, and validates regex input", () => {
    render(<App />);

    expect(screen.getByText("Secure Headers Scanner")).toBeInTheDocument();
    expect(screen.getByText("Taramayı Başlat")).toBeInTheDocument();

    // Switch language to EN
    const langBtn = screen.getByRole("button", { name: "Toggle language" });
    fireEvent.click(langBtn);
    expect(screen.getByText("Start Scan")).toBeInTheDocument();

    // Open filter panel and enter an invalid regex
    fireEvent.click(screen.getByText("Show Filters"));
    fireEvent.click(screen.getByLabelText("Use Regex"));
    const input = screen.getByPlaceholderText(/Filter domains/i);
    fireEvent.change(input, { target: { value: "[broken" } });

    expect(screen.getByText(/Invalid regular expression/i)).toBeInTheDocument();
  });
});
