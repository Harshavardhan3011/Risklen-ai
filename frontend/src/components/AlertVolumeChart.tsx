import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export type VolumePoint = { day: string; value: number };

export default function AlertVolumeChart({ data }: { data: VolumePoint[] }) {
  return <ResponsiveContainer width="100%" height={245}>
    <BarChart data={data} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
      <CartesianGrid vertical={false} stroke="#edf1f5" />
      <XAxis dataKey="day" axisLine={false} tickLine={false} />
      <YAxis allowDecimals={false} axisLine={false} tickLine={false} />
      <Tooltip />
      <Bar dataKey="value" fill="#2563a8" radius={[4, 4, 0, 0]} />
    </BarChart>
  </ResponsiveContainer>;
}
