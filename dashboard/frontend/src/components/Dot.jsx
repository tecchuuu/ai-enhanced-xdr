// Numbers wear text ink; a small colored dot beside the label carries identity.
// Painting several large figures in saturated series colors makes none of them
// stand out — the color has to be scarce to mean anything.
export default function Dot({ color }) {
  return (
    <span
      aria-hidden="true"
      style={{
        display: "inline-block",
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: color,
        marginRight: 6,
        verticalAlign: "middle",
      }}
    />
  );
}
