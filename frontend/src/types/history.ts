export type ScanRecord = {
  timestamp: string;
  ports: { port: number; risk: number }[];
};

export type HostHistory = {
  ip: string;
  favourite: boolean;
  scans: ScanRecord[];
};
