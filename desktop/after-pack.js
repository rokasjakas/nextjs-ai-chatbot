'use strict';
// Sets the icon and the name/version shown in Windows (Properties, Task Manager)
// on EventSolutions.exe. electron-builder does this with rcedit, which needs
// Wine when building on Linux; resedit does the same in plain JavaScript.
const fs = require('fs');
const path = require('path');

module.exports = async function afterPack(ctx) {
  if (ctx.electronPlatformName !== 'win32') return;
  // WebGPU shader compiler (27 MB): the app does not use WebGPU
  for (const f of ['dxcompiler.dll', 'dxil.dll']) fs.rmSync(path.join(ctx.appOutDir, f), { force: true });
  const ResEdit = await import('resedit');
  const R = ResEdit.default || ResEdit;
  const pkg = ctx.packager.appInfo;
  const exe = path.join(ctx.appOutDir, 'EventSolutions.exe');
  const data = fs.readFileSync(exe);
  const exeObj = R.NtExecutable.from(data, { ignoreCert: true });
  const rs = R.NtExecutableResource.from(exeObj);
  const ico = R.Data.IconFile.from(fs.readFileSync(path.join(__dirname, 'res', 'icon.ico')));
  const groups = R.Resource.IconGroupEntry.fromEntries(rs.entries);
  const target = groups.length ? groups[0] : { id: 1, lang: 1033 };
  R.Resource.IconGroupEntry.replaceIconsForResource(rs.entries, target.id, target.lang, ico.icons.map((i) => i.data));
  const vi = R.Resource.VersionInfo.fromEntries(rs.entries)[0] || R.Resource.VersionInfo.createEmpty();
  const [a, b, c] = pkg.version.split('.').map(Number);
  vi.setFileVersion(a, b, c, 0, 1033);
  vi.setProductVersion(a, b, c, 0, 1033);
  vi.setStringValues({ lang: 1033, codepage: 1200 }, {
    FileDescription: 'Event Solutions',
    ProductName: 'Event Solutions',
    CompanyName: 'Event Solutions',
    LegalCopyright: 'Event Solutions',
    OriginalFilename: 'EventSolutions.exe',
    InternalName: 'EventSolutions',
    FileVersion: pkg.version,
    ProductVersion: pkg.version,
  });
  vi.outputToResourceEntries(rs.entries);
  rs.outputResource(exeObj);
  fs.writeFileSync(exe, Buffer.from(exeObj.generate()));
};
