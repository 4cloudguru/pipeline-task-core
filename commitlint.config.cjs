module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'chore',
        'docs',
        'test',
        'refactor',
        'ci',
        'deps',
        'security',
        'perf',
        'revert',
      ],
    ],
    'header-max-length': [2, 'always', 72],
  },
}
