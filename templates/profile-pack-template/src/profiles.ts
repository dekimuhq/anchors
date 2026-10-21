// @dekimuhq/<member>-profiles — profile descriptor registry

import type { ProfileDescriptor } from "./types.ts";

export const profiles: Record<string, ProfileDescriptor> = {
  // TODO: enumerate profiles per spec §5.
  // Example:
  // "<member>.<profile>.v1": {
  //   name: "<member>.<profile>.v1",
  //   regulator_anchor: "GDPR Art. X",
  //   required_body_fields: ["event", "profile"],
  //   requires_tsa: false,
  // },
};
