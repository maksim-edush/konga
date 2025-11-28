const path = require('path');
const sass = require('sass');

module.exports = function (grunt) {

  grunt.config.set('sass', {
    options: {
      sourceMap: true,
      style: 'expanded'
    },
    dev: {
      files: [{
        expand: true,
        cwd: 'assets/styles/',
        src: ['importer.scss'],
        dest: '.tmp/public/styles/',
        ext: '.css'
      }]
    }
  });

  // Use the Dart Sass compile API to avoid the legacy render() deprecation.
  grunt.registerMultiTask('sass', 'Compile Sass using Dart Sass', function () {
    const options = this.options({ sourceMap: true, style: 'expanded' });

    this.files.forEach((file) => {
      if (!file.src || !file.src.length) {
        grunt.log.warn(`No source files found for ${file.dest}`);
        return;
      }

      const src = file.src[0];
      const dest = file.dest;

      let result;
      try {
        result = sass.compile(path.resolve(src), {
          style: options.style,
          sourceMap: options.sourceMap,
          sourceMapIncludeSources: true
        });
      } catch (err) {
        grunt.log.error(err);
        throw err;
      }

      grunt.file.write(dest, result.css);
      grunt.log.writeln(`File ${dest} created.`);

      if (options.sourceMap && result.sourceMap) {
        const mapPath = `${dest}.map`;
        const mapContents = typeof result.sourceMap.toString === 'function'
          ? result.sourceMap.toString()
          : JSON.stringify(result.sourceMap);

        grunt.file.write(mapPath, mapContents);
        grunt.log.writeln(`File ${mapPath} created.`);
      }
    });
  });
};
