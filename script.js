const getBranchProtectionQuery = `query($owner: String!, $repo: String!) {
  repository(owner: $owner, name: $repo) {
    branchProtectionRules(first: 5) {
      nodes {
        id
        pattern
        requiredStatusChecks {
          app {
            id
          }
          context
        }
      }
    }
  }
}`

// https://docs.github.com/en/graphql/reference/input-objects#createbranchprotectionruleinput
const createBranchProtectionQuery = `mutation($repo: ID!) {
  createBranchProtectionRule(input: {
    clientMutationId: "stoe-bot-client-protection"
    repositoryId: $repo
    pattern: "main"

    requiresApprovingReviews: true
    requiredApprovingReviewCount: 1
    requiresCodeOwnerReviews: true
    restrictsReviewDismissals: false

    requiresStatusChecks: true
    requiresStrictStatusChecks: true
    requiredStatusChecks: [{
      # GitHub Actions
      appId: "MDM6QXBwMTUzNjg="
      context: "test / test"
    }]

    requiresConversationResolution: true

    requiresLinearHistory: true

    requiresCommitSignatures: true

    isAdminEnforced: false

    restrictsPushes: false

    allowsDeletions: false
    allowsForcePushes: false
  }) {
    clientMutationId
  }
}`

// // https://docs.github.com/en/graphql/reference/mutations#updatebranchprotectionrule
const updateBranchProtectionQuery = `mutation (
  $branchProtectionRuleId: ID!
  $pattern: String = "main"
) {
  updateBranchProtectionRule(input: {
    clientMutationId: "@stoe/octoherd-script-repo-settings"
    branchProtectionRuleId: $branchProtectionRuleId

    pattern: $pattern

    requiresApprovingReviews: true
    requiredApprovingReviewCount: 1
    requiresCodeOwnerReviews: true
    restrictsReviewDismissals: false

    requiresStatusChecks: true
    requiresStrictStatusChecks: true
    requiredStatusChecks: [{
      # GitHub Actions
      appId: "MDM6QXBwMTUzNjg="
      context: "test / test"
    }]

    requiresConversationResolution: true

    requiresLinearHistory: true

    requiresCommitSignatures: true

    isAdminEnforced: false

    restrictsPushes: false

    allowsDeletions: false
    allowsForcePushes: false
  }) {
    clientMutationId
  }
}`

/**
 * @param {import('@octoherd/octokit').Octokit} octokit
 * @param {import('@octokit/openapi-types').components["schemas"]["repository"]} repository
 */
export async function script(octokit, repository) {
  if (repository.archived) return
  if (repository.fork) return

  const {
    owner: {login: owner},
    name: repo,
    node_id: repoID
  } = repository

  const language = repository.language ? repository.language.toLowerCase() : null

  // branch protection
  const {
    repository: {
      branchProtectionRules: {nodes: rules}
    }
  } = await octokit.graphql(getBranchProtectionQuery, {owner, repo})

  try {
    if (rules.length === 0 && language === 'javascript') {
      await octokit.graphql(createBranchProtectionQuery, {repo: repoID})

      octokit.log.info({updated: true}, 'branch protection rule created')
    } else {
      for (const rule of rules) {
        const {pattern, id, requiredStatusChecks} = rule

        if (requiredStatusChecks.length === 0) {
          octokit.log.info({updated: false, pattern, reason: 'empty'}, 'no rules to update')
          continue
        }

        if (['main', 'master'].includes(pattern)) {
          await octokit.graphql(updateBranchProtectionQuery, {
            branchProtectionRuleId: id,
            pattern
          })

          octokit.log.info({updated: true, pattern}, 'updated branch protection rule')
        } else {
          octokit.log.info({updated: false, pattern, reason: 'skipped'}, `skipping pattern(${pattern})`)
        }
      }
    }
  } catch (error) {
    octokit.log.error(error.message)
  }

  // settings
  try {
    // https://docs.github.com/en/rest/reference/repos#enable-vulnerability-alerts
    await octokit.request('PUT /repos/{owner}/{repo}/vulnerability-alerts', {
      owner,
      repo
    })

    // https://docs.github.com/en/rest/reference/repos#enable-automated-security-fixes
    await octokit.request('PUT /repos/{owner}/{repo}/automated-security-fixes', {
      owner,
      repo
    })

    // https://docs.github.com/en/rest/reference/repos#update-a-repository
    const config = {
      owner,
      repo,
      name: repo,
      has_issues: 'yes',
      has_projects: false,
      has_wiki: false,
      allow_squash_merge: true,
      allow_merge_commit: false,
      allow_rebase_merge: false,
      allow_auto_merge: true,
      delete_branch_on_merge: true,
      security_and_analysis: {
        secret_scanning: {
          status: 'enabled'
        }
      }
    }

    if (repository.private === false) {
      delete config.security_and_analysis.secret_scanning
    }

    if (Object.keys(config.security_and_analysis).length === 0) {
      delete config.security_and_analysis
    }

    await octokit.request('PATCH /repos/{owner}/{repo}', config)

    octokit.log.info({updated: true}, 'settings applied')
  } catch (error) {
    octokit.log.warn({message: error.message}, 'settings partially/not applied')
  }

  return true
}
