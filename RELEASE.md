# Making a release #

Compile and test

Then run

  goreleaser --rm-dist --snapshot

To test the build

When happy, tag the release

  git tag -s -m "Release v1.0.XX" v1.0.XX

Push to GitHub

  git push --follow-tags origin

Then do a release build (set GITHUB token first)

  goreleaser --rm-dist
