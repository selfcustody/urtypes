[![codecov](https://codecov.io/gh/selfcustody/urtypes/branch/main/graph/badge.svg?token=LMJZ29IHSB)](https://codecov.io/gh/selfcustody/urtypes)

# urtypes

Python implementation of the [Blockchain Commons UR Types specification](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md).

## Development

Execute **tests**:
```
poetry run pytest tests
```

See **coverage**:
```
poetry run pytest --cov=urtypes --cov-report=term-missing --cov-report=html
```

**Before commit, check pylint, vulture and format with black**:
```
poetry run pylint src
poetry run vulture src
poetry run black src
```
